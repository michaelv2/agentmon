"""Command-line interface for agentmon."""

import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agentmon.analyzers import DNSBaselineAnalyzer
from agentmon.analyzers.dns_baseline import AnalyzerConfig
from agentmon.collectors import PiholeCollector
from agentmon.collectors.pihole import PiholeConfig
from agentmon.config import load_config, find_config_file
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
    )
    analyzer = DNSBaselineAnalyzer(store, analyzer_config)

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
            stats["connection_events"] += 1
            # Connection events storage not yet implemented
            if verbose:
                console.print(
                    f"[dim]Connection:[/dim] {conn_event.client}:{conn_event.src_port} -> "
                    f"{conn_event.dst_ip}:{conn_event.dst_port} ({conn_event.protocol})"
                )

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

        # Start periodic cleanup task if retention is enabled
        cleanup_task = None
        if cfg.retention_enabled:
            cleanup_task = asyncio.create_task(periodic_cleanup())

        try:
            await receiver.run_forever()
        except asyncio.CancelledError:
            pass
        finally:
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
            store.close()
            print_stats()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        # Print stats if we didn't get to the finally block
        store.close()
        print_stats()


if __name__ == "__main__":
    main()
