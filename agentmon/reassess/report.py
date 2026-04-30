"""Reassessment report dataclasses with text and JSON output."""

import json
from dataclasses import dataclass, field


@dataclass
class ReassessmentFinding:
    """A single finding from reassessment analysis."""

    category: str  # "allowlist_candidate", "blind_spot", "analyzer_review", "llm_insight"
    title: str
    description: str
    domain: str | None = None
    analyzer: str | None = None
    severity: str = "info"  # info, warning, action
    recommendation: str = ""

    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization."""
        d: dict = {
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "recommendation": self.recommendation,
        }
        if self.domain:
            d["domain"] = self.domain
        if self.analyzer:
            d["analyzer"] = self.analyzer
        return d


@dataclass
class ReassessmentReport:
    """Complete reassessment report with findings and metadata."""

    days_analyzed: int
    total_alerts: int = 0
    total_domains: int = 0
    findings: list[ReassessmentFinding] = field(default_factory=list)
    llm_analysis: str | None = None
    llm_used: bool = False

    def to_text(self) -> str:
        """Render as Rich-compatible terminal text."""
        lines: list[str] = []
        lines.append("[cyan bold]Reassessment Report[/cyan bold]")
        lines.append(f"  Period: last {self.days_analyzed} days")
        lines.append(f"  Total alerts analyzed: {self.total_alerts:,}")
        lines.append(f"  Unique domains flagged: {self.total_domains:,}")
        lines.append(f"  LLM analysis: {'yes' if self.llm_used else 'no'}")
        lines.append("")

        # LLM analysis first — most actionable, and Slack truncates long reports
        if self.llm_analysis:
            lines.append("[cyan bold]LLM Analysis Summary[/cyan bold]")
            lines.append(self.llm_analysis)
            lines.append("")

        if not self.findings:
            lines.append("[green]No findings — rules appear well-tuned.[/green]")
            return "\n".join(lines)

        # Group findings by category
        categories: dict[str, list[ReassessmentFinding]] = {}
        for f in self.findings:
            categories.setdefault(f.category, []).append(f)

        category_labels = {
            "allowlist_candidate": "Allowlist Candidates (Likely False Positives)",
            "analyzer_review": "Analyzer Review",
            "llm_insight": "LLM Insights",
            "blind_spot": "Potential Blind Spots",
        }

        # Render in label order so blind_spot is always last
        for cat in category_labels:
            items = categories.get(cat)
            if not items:
                continue
            label = category_labels[cat]
            lines.append(f"[yellow bold]{label}[/yellow bold]")
            for item in items:
                severity_style = {
                    "info": "dim",
                    "warning": "yellow",
                    "action": "red",
                }.get(item.severity, "white")

                lines.append(f"  [{severity_style}]{item.title}[/{severity_style}]")
                lines.append(f"    {item.description}")
                if item.recommendation:
                    lines.append(f"    [cyan]Recommendation:[/cyan] {item.recommendation}")
            lines.append("")

        # Render any categories not in the predefined order
        for cat, items in categories.items():
            if cat in category_labels:
                continue
            lines.append(f"[yellow bold]{cat}[/yellow bold]")
            for item in items:
                lines.append(f"  {item.title}")
                lines.append(f"    {item.description}")
                if item.recommendation:
                    lines.append(f"    [cyan]Recommendation:[/cyan] {item.recommendation}")
            lines.append("")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Render as structured JSON."""
        data = {
            "days_analyzed": self.days_analyzed,
            "total_alerts": self.total_alerts,
            "total_domains": self.total_domains,
            "llm_used": self.llm_used,
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.llm_analysis:
            data["llm_analysis"] = self.llm_analysis
        return json.dumps(data, indent=2, default=str)
