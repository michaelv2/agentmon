"""Command-line interface for agentmon."""

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from agentmon.collectors import PiholeCollector
from agentmon.collectors.pihole import PiholeConfig
from agentmon.storage import EventStore
from agentmon.analyzers import DNSBaselineAnalyzer
from agentmon.analyzers.dns_baseline import AnalyzerConfig
from agentmon.models import Severity


console = Console()


def get_default_db_path() -> Path:
    """Get the default database path."""
    return Path.home() / ".local" / "share" / "agentmon" / "events.db"


@click.group()
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the DuckDB database file",
)
@click.pass_context
def main(ctx: click.Context, db: Optional[Path]) -> None:
    """agentmon - Network agent activity monitor and auditor."""
    ctx.ensure_object(dict)

    if db is None:
        db = get_default_db_path()

    # Ensure parent directory exists
    db.parent.mkdir(parents=True, exist_ok=True)

    ctx.obj["db_path"] = db


@main.command()
@click.option("--local", type=click.Path(exists=True, path_type=Path), help="Local path to pihole-FTL.db")
@click.option("--host", type=str, help="SSH host for remote Pi-hole")
@click.option("--user", type=str, default="pi", help="SSH username")
@click.option("--key", type=click.Path(exists=True, path_type=Path), help="SSH key file")
@click.option("--batch-size", type=int, default=1000, help="Number of events to collect per batch")
@click.option("--learning", is_flag=True, help="Learning mode: build baseline without alerting")
@click.pass_context
def collect(
    ctx: click.Context,
    local: Optional[Path],
    host: Optional[str],
    user: str,
    key: Optional[Path],
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
            console.print(f"[cyan]Baseline: {stats.get('total_domains', 0)} domains from {stats.get('total_clients', 0)} clients[/cyan]")
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
                    console.print(f"  [{severity_color}][{alert.severity.value.upper()}][/{severity_color}] {alert.title}")
            else:
                console.print("[green]No alerts generated[/green]")


@main.command()
@click.option("--severity", type=click.Choice(["info", "low", "medium", "high", "critical"]), default="low")
@click.option("--limit", type=int, default=50)
@click.pass_context
def alerts(ctx: click.Context, severity: str, limit: int) -> None:
    """Show recent alerts."""
    db_path: Path = ctx.obj["db_path"]

    with EventStore(db_path) as store:
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

    with EventStore(db_path) as store:
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

    with EventStore(db_path) as store:
        analyzer = DNSBaselineAnalyzer(store)
        stats = analyzer.get_baseline_stats()

        if not stats or stats.get("total_domains", 0) == 0:
            console.print("[yellow]No baseline data yet. Run 'agentmon collect --learning' first.[/yellow]")
            return

        console.print("[cyan]Baseline Statistics[/cyan]")
        console.print(f"  Total domains: {stats.get('total_domains', 0):,}")
        console.print(f"  Total clients: {stats.get('total_clients', 0):,}")
        console.print(f"  Total queries: {stats.get('total_queries', 0):,}")

        if stats.get("earliest"):
            console.print(f"  Earliest: {stats['earliest']}")
        if stats.get("latest"):
            console.print(f"  Latest: {stats['latest']}")


if __name__ == "__main__":
    main()
