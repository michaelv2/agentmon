"""Command-line interface for agentmon."""

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agentmon.analyzers import ConnectionAnalyzer, ConnectionAnalyzerConfig, DNSBaselineAnalyzer
from agentmon.analyzers.dns_baseline import AnalyzerConfig
from agentmon.collectors import PiholeCollector
from agentmon.collectors.pihole import PiholeConfig
from agentmon.config import find_config_file, load_config, reload_tunable_config
from agentmon.models import Severity
from agentmon.policies import DeviceManager, ParentalControlAnalyzer
from agentmon.storage import EventStore

console = Console()


@click.group()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config file (default: searches standard locations)",
)
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the DuckDB database file",
)
@click.pass_context
def main(ctx: click.Context, config: Path | None, db: Path | None) -> None:
    """agentmon - Network agent activity monitor and auditor."""
    ctx.ensure_object(dict)

    # Load config file
    cfg = load_config(config)
    ctx.obj["config"] = cfg

    # CLI --db overrides config file
    if db is not None:
        cfg.db_path = db

    # Ensure parent directory exists
    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)

    ctx.obj["db_path"] = cfg.db_path

    # Show config file location if found
    config_path = config or find_config_file()
    if config_path:
        ctx.obj["config_path"] = config_path


@main.command()
@click.option(
    "--local",
    type=click.Path(exists=True, path_type=Path),
    help="Local path to pihole-FTL.db",
)
@click.option("--host", type=str, help="SSH host for remote Pi-hole")
@click.option("--user", type=str, default="pi", help="SSH username")
@click.option("--key", type=click.Path(exists=True, path_type=Path), help="SSH key file")
@click.option("--batch-size", type=int, default=1000, help="Number of events to collect per batch")
@click.option("--learning", is_flag=True, help="Learning mode: build baseline without alerting")
@click.pass_context
def collect(
    ctx: click.Context,
    local: Path | None,
    host: str | None,
    user: str,
    key: Path | None,
    batch_size: int,
    learning: bool,
) -> None:
    """Collect DNS events from Pi-hole."""
    db_path: Path = ctx.obj["db_path"]

    if not local and not host:
        console.print("[red]Error: Must specify either --local or --host[/red]")
        sys.exit(1)

    config = PiholeConfig(
        db_path=local,
        ssh_host=host,
        ssh_user=user,
        ssh_key_path=key,
        batch_size=batch_size,
    )

    collector = PiholeCollector(config)

    with EventStore(db_path) as store:
        analyzer_config = AnalyzerConfig(learning_mode=learning)
        analyzer = DNSBaselineAnalyzer(store, analyzer_config)

        console.print(f"[cyan]Collecting from {'local' if local else host}...[/cyan]")

        events = []
        try:
            if local:
                events = list(collector.collect_local())
            else:
                events = list(collector.collect_remote_ssh())
        except Exception as e:
            console.print(f"[red]Collection error: {e}[/red]")
            sys.exit(1)

        if not events:
            console.print("[yellow]No new events collected[/yellow]")
            return

        # Store events
        count = store.insert_dns_events_batch(events)
        console.print(f"[green]Collected {count} DNS events[/green]")

        # Analyze
        if learning:
            console.print("[cyan]Learning mode: building baseline only[/cyan]")
            for event in events:
                analyzer.analyze_event(event)  # Just updates baseline

            stats = analyzer.get_baseline_stats()
            domains = stats.get("total_domains", 0)
            clients = stats.get("total_clients", 0)
            console.print(f"[cyan]Baseline: {domains} domains from {clients} clients[/cyan]")
        else:
            alerts = analyzer.analyze_batch(events)

            if alerts:
                console.print(f"[yellow]Generated {len(alerts)} alerts[/yellow]")
                for alert in alerts:
                    store.insert_alert(alert)
                    severity_color = {
                        Severity.INFO: "dim",
                        Severity.LOW: "blue",
                        Severity.MEDIUM: "yellow",
                        Severity.HIGH: "red",
                        Severity.CRITICAL: "red bold",
                    }.get(alert.severity, "white")
                    sev = alert.severity.value.upper()
                    console.print(f"  [{severity_color}][{sev}][/{severity_color}] {alert.title}")
            else:
                console.print("[green]No alerts generated[/green]")


@main.command()
@click.option(
    "--severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default="low",
)
@click.option("--limit", type=int, default=50)
@click.pass_context
def alerts(ctx: click.Context, severity: str, limit: int) -> None:
    """Show recent alerts."""
    db_path: Path = ctx.obj["db_path"]

    with EventStore(db_path, read_only=True) as store:
        min_severity = Severity(severity)
        alert_list = store.get_unacknowledged_alerts(min_severity, limit)

        if not alert_list:
            console.print("[green]No unacknowledged alerts[/green]")
            return

        table = Table(title="Unacknowledged Alerts")
        table.add_column("Time", style="dim")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Client")
        table.add_column("Domain")

        for alert in alert_list:
            severity_style = {
                "info": "dim",
                "low": "blue",
                "medium": "yellow",
                "high": "red",
                "critical": "red bold",
            }.get(alert["severity"], "white")

            timestamp = alert["timestamp"]
            if isinstance(timestamp, datetime):
                time_str = timestamp.strftime("%Y-%m-%d %H:%M")
            else:
                time_str = str(timestamp)[:16]

            table.add_row(
                time_str,
                f"[{severity_style}]{alert['severity'].upper()}[/{severity_style}]",
                alert["title"][:50],
                alert.get("client", "")[:15],
                alert.get("domain", "")[:30],
            )

        console.print(table)


@main.command()
@click.option("--hours", type=int, default=24, help="Hours to look back")
@click.pass_context
def stats(ctx: click.Context, hours: int) -> None:
    """Show DNS statistics per client."""
    db_path: Path = ctx.obj["db_path"]

    with EventStore(db_path, read_only=True) as store:
        client_stats = store.get_client_stats(hours)

        if not client_stats:
            console.print("[yellow]No data for the specified time period[/yellow]")
            return

        table = Table(title=f"Client DNS Statistics (last {hours}h)")
        table.add_column("Client")
        table.add_column("Queries", justify="right")
        table.add_column("Unique Domains", justify="right")
        table.add_column("Blocked", justify="right")
        table.add_column("Block %", justify="right")

        for stat in client_stats:
            block_pct = (
                f"{100 * stat['blocked_queries'] / stat['total_queries']:.1f}%"
                if stat['total_queries'] > 0
                else "0%"
            )

            table.add_row(
                stat["client"],
                str(stat["total_queries"]),
                str(stat["unique_domains"]),
                str(stat["blocked_queries"]),
                block_pct,
            )

        console.print(table)


@main.command()
@click.pass_context
def baseline(ctx: click.Context) -> None:
    """Show baseline statistics."""
    db_path: Path = ctx.obj["db_path"]

    with EventStore(db_path, read_only=True) as store:
        analyzer = DNSBaselineAnalyzer(store)
        stats = analyzer.get_baseline_stats()

        if not stats or stats.get("total_domains", 0) == 0:
            msg = "No baseline data yet. Run 'agentmon collect --learning' first."
            console.print(f"[yellow]{msg}[/yellow]")
            return

        console.print("[cyan]Baseline Statistics[/cyan]")
        console.print(f"  Total domains: {stats.get('total_domains', 0):,}")
        console.print(f"  Total clients: {stats.get('total_clients', 0):,}")
        console.print(f"  Total queries: {stats.get('total_queries', 0):,}")

        if stats.get("earliest"):
            console.print(f"  Earliest: {stats['earliest']}")
        if stats.get("latest"):
            console.print(f"  Latest: {stats['latest']}")


@main.command()
@click.option("--dns-days", type=int, default=None, help="Delete DNS events older than N days (default: 30)")
@click.option("--alerts-days", type=int, default=None, help="Delete alerts older than N days (default: 90)")
@click.option("--vacuum", is_flag=True, help="Run VACUUM after cleanup to reclaim disk space")
@click.option("--dry-run", is_flag=True, help="Show what would be deleted without actually deleting")
@click.pass_context
def cleanup(
    ctx: click.Context,
    dns_days: int | None,
    alerts_days: int | None,
    vacuum: bool,
    dry_run: bool,
) -> None:
    """Clean up old data according to retention policy.

    Deletes DNS events and alerts older than the specified retention periods.
    Baseline tables (domain_baseline, device_activity_baseline) are not affected
    as they are bounded by design.

    Example:
        agentmon cleanup --dns-days 7 --alerts-days 30 --vacuum
    """
    cfg = ctx.obj["config"]
    db_path: Path = ctx.obj["db_path"]

    # Use config values if not specified on CLI
    dns_retention = dns_days if dns_days is not None else cfg.retention_dns_events_days
    alerts_retention = alerts_days if alerts_days is not None else cfg.retention_alerts_days

    with EventStore(db_path) as store:
        # Show current stats
        stats = store.get_table_stats()

        console.print("[cyan]Current data:[/cyan]")
        console.print(f"  DNS events: {stats['dns_events']['count']:,} rows")
        if stats['dns_events']['oldest']:
            oldest = stats['dns_events']['oldest']
            if isinstance(oldest, datetime):
                oldest_str = oldest.strftime("%Y-%m-%d")
            else:
                oldest_str = str(oldest)[:10]
            console.print(f"    Oldest: {oldest_str}")
        console.print(f"  Alerts: {stats['alerts']['count']:,} rows")
        if stats['alerts']['oldest']:
            oldest = stats['alerts']['oldest']
            if isinstance(oldest, datetime):
                oldest_str = oldest.strftime("%Y-%m-%d")
            else:
                oldest_str = str(oldest)[:10]
            console.print(f"    Oldest: {oldest_str}")
        console.print(f"  Domain baseline: {stats['domain_baseline']['count']:,} rows (not cleaned)")
        console.print(f"  Activity baseline: {stats['device_activity_baseline']['count']:,} rows (not cleaned)")
        console.print()

        if dry_run:
            console.print(f"[yellow]Dry run: would delete DNS events older than {dns_retention} days[/yellow]")
            console.print(f"[yellow]Dry run: would delete alerts older than {alerts_retention} days[/yellow]")
            return

        console.print(f"[cyan]Cleaning up (DNS: {dns_retention}d, Alerts: {alerts_retention}d)...[/cyan]")
        result = store.cleanup_old_data(dns_retention, alerts_retention)

        console.print(f"[green]Deleted {result['dns_events_deleted']:,} DNS events[/green]")
        console.print(f"[green]Deleted {result['alerts_deleted']:,} alerts[/green]")

        if vacuum:
            console.print("[cyan]Running VACUUM to reclaim disk space...[/cyan]")
            store.vacuum()
            console.print("[green]VACUUM complete[/green]")


@main.command()
@click.option("--port", type=int, default=None, help="Port to listen on (default: 1514)")
@click.option(
    "--protocol",
    type=click.Choice(["udp", "tcp", "both"]),
    default=None,
    help="Protocol to use (default: tcp)",
)
@click.option("--bind", type=str, default=None, help="Address to bind to (default: 0.0.0.0)")
@click.option("--allow", type=str, multiple=True, help="Allowed source IPs (can specify multiple)")
@click.option("--learning", is_flag=True, default=None, help="Learning mode: build baseline without alerting")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output (show each message)")
@click.option("--llm", is_flag=True, default=None, help="Enable LLM classification via Ollama")
@click.option("--llm-triage", type=str, default=None, help="Fast triage model (default: phi3:3.8b)")
@click.option("--llm-escalation", type=str, default=None, help="Thorough escalation model (default: gpt-oss:20b)")
@click.pass_context
def listen(
    ctx: click.Context,
    port: int | None,
    protocol: str | None,
    bind: str | None,
    allow: tuple[str, ...],
    learning: bool | None,
    verbose: bool,
    llm: bool | None,
    llm_triage: str | None,
    llm_escalation: str | None,
) -> None:
    """Listen for syslog messages from edge devices.

    Starts a syslog receiver that accepts messages from Pi-hole, OpenWRT,
    and other devices configured to forward logs.

    Example:
        agentmon listen --port 1514 --protocol udp

    Edge device configuration:
        Pi-hole: Add to /etc/rsyslog.d/99-agentmon.conf:
            if $programname == 'dnsmasq' then @@<hub-ip>:1514

        OpenWRT: In /etc/config/system:
            option log_ip '<hub-ip>'
            option log_port '1514'
    """
    from agentmon.collectors.syslog_parsers import route_message
    from agentmon.collectors.syslog_receiver import SyslogConfig, SyslogMessage, SyslogReceiver

    cfg = ctx.obj["config"]
    db_path: Path = ctx.obj["db_path"]

    # Use config file values, CLI overrides
    syslog_port = port if port is not None else cfg.syslog_port
    syslog_protocol = protocol if protocol is not None else cfg.syslog_protocol
    syslog_bind = bind if bind is not None else cfg.syslog_bind_address
    syslog_allowed = list(allow) if allow else cfg.syslog_allowed_ips

    use_learning = learning if learning is not None else cfg.learning_mode
    use_llm = llm if llm is not None else cfg.llm_enabled
    use_triage = llm_triage if llm_triage is not None else cfg.llm_triage_model
    use_escalation = llm_escalation if llm_escalation is not None else cfg.llm_escalation_model

    syslog_config = SyslogConfig(
        port=syslog_port,
        protocol=syslog_protocol,
        bind_address=syslog_bind,
        allowed_ips=syslog_allowed,
    )

    # Security warning: binding to all interfaces without IP allowlist
    if syslog_bind in ("0.0.0.0", "::") and not syslog_allowed:
        console.print(
            "[yellow bold]SECURITY WARNING:[/yellow bold] "
            "[yellow]Syslog receiver bound to all interfaces without IP allowlist![/yellow]"
        )
        console.print(
            "[yellow]This exposes your system to the entire network. "
            "Consider using --allow to restrict source IPs or --bind to bind to a specific interface.[/yellow]"
        )
        console.print()

    # Set up logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Show config source
    if "config_path" in ctx.obj:
        console.print(f"[dim]Config: {ctx.obj['config_path']}[/dim]")
    if cfg.known_bad_patterns:
        console.print(f"[dim]Loaded {len(cfg.known_bad_patterns)} known-bad patterns[/dim]")

    # Counters for stats
    stats = {
        "messages_received": 0,
        "dns_events": 0,
        "connection_events": 0,
        "alerts": 0,
    }

    store = EventStore(db_path)
    store.connect()

    analyzer_config = AnalyzerConfig(
        learning_mode=use_learning,
        llm_enabled=use_llm,
        llm_triage_model=use_triage,
        llm_escalation_model=use_escalation,
        known_bad_patterns=cfg.known_bad_patterns,
        allowlist=cfg.allowlist,
        ignore_suffixes=cfg.ignore_suffixes,
        entropy_threshold=cfg.entropy_threshold,
        entropy_min_length=cfg.entropy_min_length,
        alert_dedup_window=cfg.alert_dedup_window,
        dga_min_queries_suppress=cfg.dga_min_queries_suppress,
        dga_min_clients_suppress=cfg.dga_min_clients_suppress,
        trusted_infrastructure=cfg.trusted_infrastructure,
        ocsp_spike_enabled=cfg.ocsp_spike_enabled,
        ocsp_spike_threshold=cfg.ocsp_spike_threshold,
        ocsp_spike_severity=cfg.ocsp_spike_severity,
        watched_domains=cfg.watched_domains,
        watched_domain_volume_threshold=cfg.watched_domain_volume_threshold,
    )
    # Initialize threat feed manager if configured
    threat_feed_manager = None
    if cfg.threat_feeds_enabled:
        from agentmon.threat_feeds import ThreatFeedManager

        threat_feed_manager = ThreatFeedManager(
            cache_dir=cfg.threat_feeds_cache_dir,
            update_interval_hours=cfg.threat_feeds_update_interval_hours,
        )
        console.print("[dim]Threat intelligence feeds enabled[/dim]")

    # Initialize VirusTotal client if API key is configured
    vt_client = None
    if cfg.virustotal_api_key:
        from agentmon.threat_intel.virustotal import VirusTotalClient

        vt_client = VirusTotalClient(api_key=cfg.virustotal_api_key)
        console.print("[dim]VirusTotal API enabled[/dim]")

    analyzer = DNSBaselineAnalyzer(store, analyzer_config, threat_feed_manager, vt_client)

    # Initialize Slack notifier if configured
    slack_notifier = None
    if cfg.slack_enabled and cfg.slack_webhook_url:
        from agentmon.notifiers.slack import SlackNotifier, SlackConfig

        slack_config = SlackConfig(
            webhook_url=cfg.slack_webhook_url,
            min_severity=Severity(cfg.slack_min_severity),
            enabled=True,
        )
        slack_notifier = SlackNotifier(slack_config)

    # Initialize parental control analyzer if configured
    parental_analyzer = None
    if cfg.parental_controls_enabled and cfg.parental_devices and cfg.parental_policies:
        device_manager = DeviceManager(cfg.parental_devices, cfg.parental_policies)
        parental_analyzer = ParentalControlAnalyzer(device_manager)

    # Initialize device activity analyzer if configured
    device_activity_analyzer = None
    if cfg.device_activity_enabled:
        from agentmon.analyzers.device_activity import DeviceActivityAnalyzer, DeviceActivityConfig

        activity_config = DeviceActivityConfig(
            enabled=True,
            learning_days=cfg.device_activity_learning_days,
            activity_threshold=cfg.device_activity_threshold,
            min_samples=cfg.device_activity_min_samples,
            alert_severity=Severity(cfg.device_activity_severity),
            devices=cfg.device_activity_devices,
        )
        device_activity_analyzer = DeviceActivityAnalyzer(store, activity_config)

    # Initialize volume anomaly analyzer if configured
    volume_anomaly_analyzer = None
    if cfg.volume_anomaly_enabled:
        from agentmon.analyzers.volume_anomaly import VolumeAnomalyAnalyzer, VolumeAnomalyConfig

        volume_config = VolumeAnomalyConfig(
            enabled=True,
            learning_days=cfg.volume_anomaly_learning_days,
            sensitivity_sigma=cfg.volume_anomaly_sensitivity_sigma,
            min_samples=cfg.volume_anomaly_min_samples,
            min_query_threshold=cfg.volume_anomaly_min_query_threshold,
            min_domain_threshold=cfg.volume_anomaly_min_domain_threshold,
            sustained_hours=cfg.volume_anomaly_sustained_hours,
            spike_severity=Severity(cfg.volume_anomaly_spike_severity),
            diversity_severity=Severity(cfg.volume_anomaly_diversity_severity),
            sustained_severity=Severity(cfg.volume_anomaly_sustained_severity),
            devices=cfg.volume_anomaly_devices,
        )
        volume_anomaly_analyzer = VolumeAnomalyAnalyzer(store, volume_config)

    # Initialize client resolver if configured
    client_resolver = None
    if cfg.resolver_enabled:
        from agentmon.resolver import ClientResolver, ResolverConfig

        resolver_config = ResolverConfig(
            enabled=True,
            dns_server=cfg.resolver_dns_server,
            cache_ttl=cfg.resolver_cache_ttl,
            strip_suffix=cfg.resolver_strip_suffix,
            mappings=cfg.resolver_mappings,
        )
        client_resolver = ClientResolver(resolver_config)

    # Initialize connection analyzer
    conn_analyzer_config = ConnectionAnalyzerConfig(learning_mode=use_learning)
    connection_analyzer = ConnectionAnalyzer(store, conn_analyzer_config)

    # Initialize OODA watchdog if configured
    watchdog = None
    if cfg.watchdog_enabled and cfg.anthropic_api_key:
        from agentmon.llm.anthropic_client import AnthropicClient, AnthropicConfig
        from agentmon.watchdog import OODAWatchdog

        watchdog_llm_config = AnthropicConfig(
            model=cfg.watchdog_model,
            max_tokens=cfg.watchdog_max_tokens_per_cycle,
        )
        watchdog_llm = AnthropicClient(cfg.anthropic_api_key, watchdog_llm_config)
        if watchdog_llm.available:
            watchdog = OODAWatchdog(
                store=store,
                llm=watchdog_llm,
                interval_minutes=cfg.watchdog_interval_minutes,
                max_tokens_per_cycle=cfg.watchdog_max_tokens_per_cycle,
                window_minutes=cfg.watchdog_window_minutes,
                config_path=ctx.obj.get("config_path"),
            )

    def handle_message(msg: SyslogMessage) -> None:
        """Process a received syslog message."""
        stats["messages_received"] += 1

        if verbose:
            console.print(
                f"[dim]{msg.timestamp.strftime('%H:%M:%S')}[/dim] "
                f"[cyan]{msg.hostname}[/cyan] "
                f"[yellow]{msg.tag}[/yellow]: {msg.message[:80]}"
            )

        # Route to appropriate parser
        dns_event, conn_event = route_message(msg)

        if dns_event:
            # Handle block notifications (correlate with recent query)
            if dns_event.client == "__BLOCK_NOTIFICATION__":
                # Update the most recent query for this domain to blocked=True
                updated = store.mark_domain_blocked(dns_event.domain)
                if updated and verbose:
                    console.print(f"[yellow]  -> blocked: {dns_event.domain}[/yellow]")
                return

            # Early filtering: skip domains matching ignore_suffixes before
            # storage and resolution to avoid database bloat from noisy queries
            # (e.g., DNS-SD .arpa floods)
            domain_lower = dns_event.domain.lower()
            if any(domain_lower.endswith(suffix) for suffix in cfg.ignore_suffixes):
                return

            # Resolve client IP to hostname (if resolver is enabled)
            # This allows baselines to survive DHCP changes
            if client_resolver:
                original_client = dns_event.client
                resolved_client = client_resolver.resolve(dns_event.client)
                if resolved_client != original_client:
                    # Create new event with resolved client (DNSEvent is frozen)
                    dns_event = type(dns_event)(
                        timestamp=dns_event.timestamp,
                        client=resolved_client,
                        domain=dns_event.domain,
                        query_type=dns_event.query_type,
                        blocked=dns_event.blocked,
                    )
                    if verbose:
                        console.print(f"[dim]  Resolved: {original_client} → {resolved_client}[/dim]")

            stats["dns_events"] += 1
            store.insert_dns_event(dns_event)

            # Feed DNS event to connection analyzer for correlation
            connection_analyzer.track_dns_answer(dns_event)

            # Analyze for threats (security)
            alerts = analyzer.analyze_event(dns_event)

            # Analyze for parental control violations
            if parental_analyzer:
                pc_alerts = parental_analyzer.analyze_event(dns_event)
                alerts.extend(pc_alerts)

            # Analyze for device activity anomalies
            if device_activity_analyzer:
                activity_alerts = device_activity_analyzer.analyze_event(dns_event)
                alerts.extend(activity_alerts)

            # Analyze for volume anomalies
            if volume_anomaly_analyzer:
                volume_alerts = volume_anomaly_analyzer.analyze_event(dns_event)
                alerts.extend(volume_alerts)

            for alert in alerts:
                stats["alerts"] += 1
                store.insert_alert(alert)
                severity_color = {
                    Severity.INFO: "dim",
                    Severity.LOW: "blue",
                    Severity.MEDIUM: "yellow",
                    Severity.HIGH: "red",
                    Severity.CRITICAL: "red bold",
                }.get(alert.severity, "white")
                console.print(
                    f"[{severity_color}][ALERT][/{severity_color}] "
                    f"{alert.title} - {alert.domain}"
                )
                if alert.llm_analysis:
                    console.print(f"  [dim]LLM: {alert.llm_analysis}[/dim]")

                # Send to Slack (fire-and-forget, don't block)
                if slack_notifier:
                    asyncio.get_event_loop().create_task(slack_notifier.send_alert(alert))

        if conn_event:
            # Resolve client IP to hostname (if resolver is enabled)
            if client_resolver:
                original_client = conn_event.client
                resolved_client = client_resolver.resolve(conn_event.client)
                if resolved_client != original_client:
                    conn_event = type(conn_event)(
                        timestamp=conn_event.timestamp,
                        client=resolved_client,
                        src_port=conn_event.src_port,
                        dst_ip=conn_event.dst_ip,
                        dst_port=conn_event.dst_port,
                        protocol=conn_event.protocol,
                        bytes_sent=conn_event.bytes_sent,
                        bytes_recv=conn_event.bytes_recv,
                        duration_seconds=conn_event.duration_seconds,
                        dns_domain=conn_event.dns_domain,
                    )

            stats["connection_events"] += 1

            # Correlate with DNS and detect direct IP access
            conn_event, conn_alerts = connection_analyzer.analyze_event(conn_event)
            store.insert_connection_event(conn_event)

            if verbose:
                domain_str = f" ({conn_event.dns_domain})" if conn_event.dns_domain else ""
                console.print(
                    f"[dim]Connection:[/dim] {conn_event.client}:{conn_event.src_port} -> "
                    f"{conn_event.dst_ip}:{conn_event.dst_port} ({conn_event.protocol}){domain_str}"
                )

            for alert in conn_alerts:
                stats["alerts"] += 1
                store.insert_alert(alert)
                severity_color = {
                    Severity.INFO: "dim",
                    Severity.LOW: "blue",
                    Severity.MEDIUM: "yellow",
                    Severity.HIGH: "red",
                    Severity.CRITICAL: "red bold",
                }.get(alert.severity, "white")
                console.print(
                    f"[{severity_color}][ALERT][/{severity_color}] "
                    f"{alert.title}"
                )

                # Send to Slack (fire-and-forget, don't block)
                if slack_notifier:
                    asyncio.get_event_loop().create_task(slack_notifier.send_alert(alert))

    def print_stats() -> None:
        """Print final statistics."""
        console.print()
        console.print("[green]Syslog receiver stopped[/green]")
        console.print(f"  Messages received: {stats['messages_received']:,}")
        console.print(f"  DNS events: {stats['dns_events']:,}")
        console.print(f"  Connection events: {stats['connection_events']:,}")
        console.print(f"  Alerts generated: {stats['alerts']:,}")

    async def periodic_cleanup() -> None:
        """Run cleanup periodically."""
        interval_seconds = cfg.retention_cleanup_interval_hours * 3600
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                result = store.cleanup_old_data(
                    cfg.retention_dns_events_days,
                    cfg.retention_alerts_days,
                )
                if result["dns_events_deleted"] > 0 or result["alerts_deleted"] > 0:
                    console.print(
                        f"[dim]Cleanup: deleted {result['dns_events_deleted']} events, "
                        f"{result['alerts_deleted']} alerts[/dim]"
                    )
            except Exception as e:
                console.print(f"[red]Cleanup error: {e}[/red]")

    async def run() -> None:
        """Run the syslog receiver."""
        receiver = SyslogReceiver(syslog_config, handle_message)

        # Run startup cleanup if retention is enabled
        if cfg.retention_enabled:
            try:
                result = store.cleanup_old_data(
                    cfg.retention_dns_events_days,
                    cfg.retention_alerts_days,
                )
                if result["dns_events_deleted"] > 0 or result["alerts_deleted"] > 0:
                    console.print(
                        f"[cyan]Startup cleanup: deleted {result['dns_events_deleted']} events, "
                        f"{result['alerts_deleted']} alerts[/cyan]"
                    )
            except Exception as e:
                console.print(f"[yellow]Startup cleanup failed: {e}[/yellow]")

        console.print(f"[green]Starting syslog receiver on {syslog_bind}:{syslog_port} ({syslog_protocol})[/green]")

        # Warn if retention is disabled and database is large
        if not cfg.retention_enabled and db_path.exists():
            db_size_mb = db_path.stat().st_size / (1024 * 1024)
            if db_size_mb > 500:
                console.print(
                    f"[yellow bold]WARNING:[/yellow bold] "
                    f"[yellow]Database is {db_size_mb:.0f}MB and retention policy is disabled.[/yellow]"
                )
                console.print(
                    "[yellow]Consider enabling [retention] in config or running 'agentmon cleanup'.[/yellow]"
                )
                console.print()

        if use_learning:
            console.print("[cyan]Learning mode: building baseline only[/cyan]")
        if use_llm:
            console.print(f"[cyan]LLM triage: {use_triage} → escalation: {use_escalation}[/cyan]")
        if syslog_allowed:
            console.print(f"[cyan]Allowed IPs: {', '.join(syslog_allowed)}[/cyan]")
        if slack_notifier:
            console.print(f"[cyan]Slack notifications: {cfg.slack_min_severity}+ severity[/cyan]")
        if parental_analyzer:
            device_count = len(cfg.parental_devices)
            policy_count = len(cfg.parental_policies)
            console.print(f"[cyan]Parental controls: {device_count} devices, {policy_count} policies[/cyan]")
        if device_activity_analyzer:
            device_count = len(cfg.device_activity_devices)
            console.print(
                f"[cyan]Device activity: learning={cfg.device_activity_learning_days}d, "
                f"threshold={cfg.device_activity_threshold}q/h, "
                f"{device_count} named devices[/cyan]"
            )
        if volume_anomaly_analyzer:
            device_count = len(cfg.volume_anomaly_devices)
            console.print(
                f"[cyan]Volume anomaly: learning={cfg.volume_anomaly_learning_days}d, "
                f"sigma={cfg.volume_anomaly_sensitivity_sigma}, "
                f"sustained={cfg.volume_anomaly_sustained_hours}h, "
                f"{device_count} named devices[/cyan]"
            )
        if watchdog:
            console.print(
                f"[cyan]OODA watchdog: interval={cfg.watchdog_interval_minutes}m, "
                f"model={cfg.watchdog_model}[/cyan]"
            )
        if client_resolver:
            mapping_count = len(cfg.resolver_mappings)
            console.print(
                f"[cyan]Client resolver: cache_ttl={cfg.resolver_cache_ttl}s, "
                f"strip_suffix={cfg.resolver_strip_suffix}, "
                f"{mapping_count} explicit mappings[/cyan]"
            )
        if cfg.retention_enabled:
            console.print(
                f"[cyan]Retention: dns_events={cfg.retention_dns_events_days}d, "
                f"alerts={cfg.retention_alerts_days}d, "
                f"interval={cfg.retention_cleanup_interval_hours}h[/cyan]"
            )
        console.print("[dim]Press Ctrl+C to stop[/dim]")
        console.print()

        # Write pidfile for SIGHUP-based config reload
        run_dir = Path("/run")
        pid_path = run_dir / "agentmon.pid" if os.access(run_dir, os.W_OK) else cfg.db_path.parent / "agentmon.pid"
        pid_path.write_text(str(os.getpid()))
        logger = logging.getLogger("agentmon.cli")
        logger.info("PID %d written to %s", os.getpid(), pid_path)

        # Resolve config_path for reload (may be None if using search)
        reload_config_path: Path | None = ctx.obj.get("config_path")

        def handle_sighup() -> None:
            """Reload tunable config fields on SIGHUP."""
            nonlocal cfg, parental_analyzer

            new_cfg, changes = reload_tunable_config(reload_config_path, cfg)
            if not changes:
                logger.info("SIGHUP received, no config changes detected")
                return

            for change in changes:
                logger.info("Config reload: %s", change)

            # Update analyzer tunable fields
            analyzer.config.allowlist = new_cfg.allowlist
            analyzer.config.known_bad_patterns = new_cfg.known_bad_patterns
            analyzer.config.entropy_threshold = new_cfg.entropy_threshold
            analyzer.config.entropy_min_length = new_cfg.entropy_min_length
            analyzer.config.ignore_suffixes = new_cfg.ignore_suffixes

            # Recreate dedup cache if window changed
            if new_cfg.alert_dedup_window != cfg.alert_dedup_window:
                from cachetools import TTLCache
                analyzer.config.alert_dedup_window = new_cfg.alert_dedup_window
                analyzer._alert_cache = TTLCache(
                    maxsize=5000, ttl=new_cfg.alert_dedup_window
                )

            # Rebuild parental control analyzer if policies/devices changed
            if parental_analyzer and (
                new_cfg.parental_devices != cfg.parental_devices
                or new_cfg.parental_policies != cfg.parental_policies
            ):
                device_manager = DeviceManager(
                    new_cfg.parental_devices, new_cfg.parental_policies
                )
                parental_analyzer = ParentalControlAnalyzer(device_manager)

            # Update the active config so ignore_suffixes in handle_message
            # and other references use the new values
            cfg = new_cfg

        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGHUP, handle_sighup)

        # Start periodic cleanup task if retention is enabled
        cleanup_task = None
        if cfg.retention_enabled:
            cleanup_task = asyncio.create_task(periodic_cleanup())

        # Start watchdog periodic loop if configured
        watchdog_task = None
        if watchdog:
            watchdog_task = asyncio.create_task(watchdog.run_periodic())

        try:
            await receiver.run_forever()
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        finally:
            # run_forever() replaced SIGINT/SIGTERM handlers with no-ops
            # so Ctrl+C during cleanup won't raise KeyboardInterrupt.
            if watchdog_task:
                watchdog.stop()
                watchdog_task.cancel()
                try:
                    await watchdog_task
                except asyncio.CancelledError:
                    pass
            if cleanup_task:
                cleanup_task.cancel()
                try:
                    await cleanup_task
                except asyncio.CancelledError:
                    pass
            if slack_notifier:
                await slack_notifier.close()
            if device_activity_analyzer:
                device_activity_analyzer.flush()
            if volume_anomaly_analyzer:
                volume_anomaly_analyzer.flush()
            store.close()
            pid_path.unlink(missing_ok=True)
            # Restore default signal handling now that cleanup is done
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.remove_signal_handler(sig)
                except (NotImplementedError, ValueError, RuntimeError):
                    pass
            print_stats()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        # Safety net — if KeyboardInterrupt escapes despite no-op handlers
        store.close()
        print_stats()


@main.command()
@click.pass_context
def feeds(ctx: click.Context) -> None:
    """Manage threat intelligence feeds.

    Shows status of downloaded threat feeds and allows manual updates.
    """
    cfg = ctx.obj["config"]

    if not cfg.threat_feeds_enabled:
        console.print("[yellow]Threat feeds are disabled in config[/yellow]")
        console.print("Enable with [cyan][threat_feeds] enabled = true[/cyan]")
        return

    from agentmon.threat_feeds import ThreatFeedManager

    manager = ThreatFeedManager(
        cache_dir=cfg.threat_feeds_cache_dir,
        update_interval_hours=cfg.threat_feeds_update_interval_hours,
    )

    # Update feeds
    console.print("[cyan]Updating threat intelligence feeds...[/cyan]")
    manager.update_feeds()

    # Show stats
    stats = manager.get_stats()

    console.print(f"\n[green]Total malicious domains: {stats['total_domains']:,}[/green]\n")

    if stats["feeds"]:
        from rich.table import Table

        table = Table(title="Threat Feeds")
        table.add_column("Feed", style="cyan")
        table.add_column("Domains", justify="right", style="yellow")
        table.add_column("Last Updated", style="dim")
        table.add_column("Age (hours)", justify="right", style="dim")

        for feed in stats["feeds"]:
            age_style = "green" if feed["age_hours"] < 24 else "yellow" if feed["age_hours"] < 48 else "red"
            table.add_row(
                feed["name"],
                f"{feed['domains']:,}",
                feed["updated"],
                f"[{age_style}]{feed['age_hours']}[/{age_style}]",
            )

        console.print(table)
    else:
        console.print("[yellow]No feeds cached yet[/yellow]")

    console.print(f"\n[dim]Cache directory: {cfg.threat_feeds_cache_dir}[/dim]")


@main.command()
@click.option("--host", type=str, default=None, help="Host to bind to (default: 127.0.0.1)")
@click.option("--port", type=int, default=None, help="Port to listen on (default: 8080)")
@click.pass_context
def dashboard(ctx: click.Context, host: str | None, port: int | None) -> None:
    """Start the alert review dashboard.

    Opens a web UI for triaging flagged domains, marking false positives,
    adding to allowlist, and sending domains to Claude for analysis.

    Note: The dashboard needs read-write database access. Stop 'agentmon listen'
    before starting the dashboard to avoid lock conflicts.

    Example:
        agentmon dashboard --port 8080
    """
    cfg = ctx.obj["config"]

    dash_host = host if host is not None else cfg.dashboard_host
    dash_port = port if port is not None else cfg.dashboard_port

    try:
        import uvicorn
        from agentmon.dashboard.app import create_app
    except ImportError:
        console.print("[red]Dashboard dependencies not installed.[/red]")
        console.print("Install with: [cyan]pip install -e '.[dev]'[/cyan]")
        console.print("Required: fastapi, uvicorn, jinja2")
        sys.exit(1)

    app = create_app(cfg)

    console.print(f"[green]Starting dashboard at http://{dash_host}:{dash_port}[/green]")
    if cfg.anthropic_api_key:
        console.print("[dim]Anthropic (Claude) LLM review: enabled[/dim]")
    else:
        console.print("[dim]Anthropic LLM review: disabled (set ANTHROPIC_API_KEY)[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()

    uvicorn.run(app, host=dash_host, port=dash_port, log_level="info")


@main.command()
@click.option("--days", type=int, default=7, help="Days to look back (default: 7)")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout",
)
@click.pass_context
def reassess(
    ctx: click.Context,
    days: int,
    output_format: str,
    output_path: Path | None,
) -> None:
    """Analyze alert patterns and suggest rule improvements.

    Reviews recent alerts to identify false positive noise, blind spots,
    and rule tuning opportunities. Optionally uses Claude Sonnet for
    deeper analysis when ANTHROPIC_API_KEY is set.

    Examples:
        agentmon reassess --days 7
        agentmon reassess --format json --output report.json
    """
    cfg = ctx.obj["config"]
    db_path: Path = ctx.obj["db_path"]

    # Initialize Anthropic client if available
    anthropic_client = None
    if cfg.anthropic_api_key:
        try:
            from agentmon.llm.anthropic_client import AnthropicClient

            anthropic_client = AnthropicClient(cfg.anthropic_api_key)
            if not anthropic_client.available:
                anthropic_client = None
        except Exception:
            pass

    from agentmon.reassess.analyzer import ReassessmentAnalyzer

    with EventStore(db_path, read_only=True) as store:
        analyzer = ReassessmentAnalyzer(store, anthropic_client)

        if anthropic_client:
            console.print("[dim]Using Claude Sonnet for analysis...[/dim]")
        else:
            console.print("[dim]Heuristic analysis only (set ANTHROPIC_API_KEY for LLM)[/dim]")

        report = analyzer.analyze(days=days)

    # Output
    if output_format == "json":
        output_text = report.to_json()
    else:
        output_text = report.to_text()

    if output_path:
        output_path.write_text(output_text)
        console.print(f"[green]Report written to {output_path}[/green]")
    else:
        if output_format == "json":
            console.print(output_text)
        else:
            console.print(output_text, highlight=False)


if __name__ == "__main__":
    main()
