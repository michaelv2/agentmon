"""Reassessment orchestrator: queries + heuristics + optional LLM analysis."""

from __future__ import annotations

import logging

from agentmon.analyzers.entropy import is_trusted_infrastructure
from agentmon.config import Config
from agentmon.reassess.queries import (
    get_analyzer_false_positive_rates,
    get_high_frequency_alert_domains,
    get_recent_alert_sample,
    get_unflagged_high_traffic_domains,
)
from agentmon.reassess.report import ReassessmentFinding, ReassessmentReport
from agentmon.storage import EventStore

logger = logging.getLogger(__name__)

LLM_SYSTEM_PROMPT = (
    "You are a network security engineer reviewing DNS monitoring rules for a home/small-office "
    "network. Your job is to analyze alert patterns and suggest improvements to reduce false "
    "positives while maintaining detection coverage.\n\n"
    "The current analyzer configuration is provided below the alert data. Do NOT recommend "
    "allowlisting domains that are already covered by the allowlist, trusted_infrastructure, "
    "or ignore_suffixes. Focus on gaps and domains that are genuinely missing.\n\n"
    "Provide concise, actionable recommendations in these categories:\n"
    "1. Domains that should be allowlisted (clearly benign but frequently alerting)\n"
    "2. Patterns that need tuning (too broad or too narrow)\n"
    "3. Blind spots to investigate (high-traffic domains never flagged)\n"
    "4. Classifier guidance gaps: if alert patterns suggest the triage/escalation LLM is "
    "systematically misclassifying a class of domains (e.g., infrastructure probes as DGA, "
    "reserved TLDs as suspicious), recommend what the classification prompt should be taught "
    "rather than just allowlisting individual domains\n"
    "5. General rule health observations\n\n"
    "Be specific: name domains, analyzers, and thresholds. Keep your response under 500 words."
)


class ReassessmentAnalyzer:
    """Orchestrates reassessment analysis combining heuristics and optional LLM."""

    def __init__(
        self,
        store: EventStore,
        anthropic_client: object | None = None,
        config: Config | None = None,
    ) -> None:
        self.store = store
        self._llm = anthropic_client
        self._config = config or Config()

    def _is_already_suppressed(self, domain: str) -> bool:
        """Check if a domain is already handled by allowlist, ignore_suffixes, or trusted infra."""
        # Check ignore_suffixes
        if any(domain.endswith(s) for s in self._config.ignore_suffixes):
            return True
        # Check allowlist (exact + wildcard, same logic as dns_baseline)
        for entry in self._config.allowlist:
            if entry.startswith("*."):
                suffix = entry[1:]  # ".example.com"
                parent = entry[2:]  # "example.com"
                if domain == parent or domain.endswith(suffix):
                    return True
            elif domain == entry:
                return True
        # Check trusted_infrastructure
        return is_trusted_infrastructure(domain, frozenset(self._config.trusted_infrastructure))

    def analyze(self, days: int = 7) -> ReassessmentReport:
        """Run full reassessment analysis.

        Args:
            days: Number of days to look back.

        Returns:
            ReassessmentReport with findings and optional LLM analysis.
        """
        report = ReassessmentReport(days_analyzed=days)

        conn = self.store.conn

        # Gather data
        high_freq_domains = get_high_frequency_alert_domains(conn, days=days)
        unflagged_domains = get_unflagged_high_traffic_domains(conn)
        analyzer_rates = get_analyzer_false_positive_rates(conn, days=days)
        alert_sample = get_recent_alert_sample(conn, days=days)

        if high_freq_domains:
            report.total_alerts = sum(d["alert_count"] for d in high_freq_domains)
        else:
            report.total_alerts = 0
        report.total_domains = len(high_freq_domains)

        # Apply heuristic rules
        self._find_allowlist_candidates(report, high_freq_domains)
        self._find_blind_spots(report, unflagged_domains)
        self._find_analyzer_issues(report, analyzer_rates)

        # Optional LLM analysis
        if self._llm is not None and hasattr(self._llm, "complete"):
            self._run_llm_analysis(
                report, high_freq_domains, unflagged_domains, analyzer_rates, alert_sample,
            )

        return report

    def _find_allowlist_candidates(
        self,
        report: ReassessmentReport,
        high_freq: list[dict],
    ) -> None:
        """Heuristic: domain with >10 alerts and >50% FP rate → suggest allowlist."""
        for domain_data in high_freq:
            domain = domain_data["domain"]
            alert_count = domain_data["alert_count"]
            fp_count = domain_data["fp_count"]

            if alert_count > 10 and fp_count > 0:
                fp_rate = fp_count / alert_count
                if fp_rate > 0.5 and not self._is_already_suppressed(domain.lower()):
                    report.findings.append(ReassessmentFinding(
                        category="allowlist_candidate",
                        title=f"{domain} — {fp_rate:.0%} false positive rate",
                        description=(
                            f"{alert_count} alerts, {fp_count} marked as false positive. "
                            f"Analyzers: {', '.join(domain_data.get('analyzers', []))}"
                        ),
                        domain=domain,
                        severity="action",
                        recommendation=f"Add '{domain}' to allowlist",
                    ))

    def _find_blind_spots(
        self,
        report: ReassessmentReport,
        unflagged: list[dict],
    ) -> None:
        """Heuristic: domain queried by 5+ clients, never flagged → blind spot."""
        for domain_data in unflagged:
            if domain_data["client_count"] >= 5:
                report.findings.append(ReassessmentFinding(
                    category="blind_spot",
                    title=(
                        f"{domain_data['domain']} — "
                        f"{domain_data['client_count']} clients, never flagged"
                    ),
                    description=(
                        f"Queried by {domain_data['client_count']} distinct clients "
                        f"({domain_data['total_queries']} total queries) "
                        f"but never generated an alert."
                    ),
                    domain=domain_data["domain"],
                    severity="info",
                    recommendation="Review whether this domain should be monitored",
                ))

    def _find_analyzer_issues(
        self,
        report: ReassessmentReport,
        analyzer_rates: list[dict],
    ) -> None:
        """Heuristic: analyzer with >30% FP rate → suggest rule review."""
        for rate_data in analyzer_rates:
            fp_rate = rate_data["fp_rate"] or 0.0
            if fp_rate > 0.3 and rate_data["total_alerts"] >= 5:
                report.findings.append(ReassessmentFinding(
                    category="analyzer_review",
                    title=f"{rate_data['analyzer']} — {fp_rate:.0%} false positive rate",
                    description=(
                        f"{rate_data['total_alerts']} total alerts, "
                        f"{rate_data['fp_count']} false positives."
                    ),
                    analyzer=rate_data["analyzer"],
                    severity="warning",
                    recommendation=f"Review rules for '{rate_data['analyzer']}' analyzer",
                ))

    def _run_llm_analysis(
        self,
        report: ReassessmentReport,
        high_freq: list[dict],
        unflagged: list[dict],
        analyzer_rates: list[dict],
        alert_sample: list[dict],
    ) -> None:
        """Run optional LLM analysis using Anthropic client."""
        # Build compact prompt from query results (~4000 tokens max)
        sections: list[str] = []

        if high_freq:
            lines = ["## High-Frequency Alert Domains (potential false positives)"]
            for d in high_freq[:20]:
                if d["alert_count"]:
                    fp_pct = f"{100 * d['fp_count'] / d['alert_count']:.0f}%"
                else:
                    fp_pct = "0%"
                lines.append(
                    f"- {d['domain']}: {d['alert_count']} alerts, {fp_pct} FP, "
                    f"analyzers={d.get('analyzers', [])}"
                )
            sections.append("\n".join(lines))

        if unflagged:
            lines = ["## Unflagged High-Traffic Domains (potential blind spots)"]
            for d in unflagged[:15]:
                lines.append(
                    f"- {d['domain']}: {d['client_count']} clients, {d['total_queries']} queries"
                )
            sections.append("\n".join(lines))

        if analyzer_rates:
            lines = ["## Analyzer Performance"]
            for a in analyzer_rates:
                fp_pct = f"{100 * (a['fp_rate'] or 0):.0f}%"
                lines.append(
                    f"- {a['analyzer']}: {a['total_alerts']} alerts, {fp_pct} FP rate"
                )
            sections.append("\n".join(lines))

        if alert_sample:
            lines = ["## Recent Alert Sample"]
            for a in alert_sample[:30]:
                fp_marker = " [FP]" if a.get("false_positive") else ""
                lines.append(
                    f"- [{a['severity']}] {a.get('domain', 'N/A')} — "
                    f"{a['title'][:60]} (analyzer={a.get('analyzer', 'N/A')}){fp_marker}"
                )
            sections.append("\n".join(lines))

        # Include current config so the LLM knows what's already suppressed
        config_lines = ["## Current Analyzer Config"]
        if self._config.allowlist:
            config_lines.append("Allowlist: " + ", ".join(sorted(self._config.allowlist)))
        if self._config.trusted_infrastructure:
            config_lines.append(
                "Trusted infrastructure: "
                + ", ".join(sorted(self._config.trusted_infrastructure))
            )
        if self._config.ignore_suffixes:
            config_lines.append(
                "Ignored suffixes: " + ", ".join(self._config.ignore_suffixes)
            )
        config_lines.append(f"Entropy threshold: {self._config.entropy_threshold}")
        config_lines.append(
            f"DGA suppression: >{self._config.dga_min_queries_suppress} queries "
            f"from >{self._config.dga_min_clients_suppress} clients"
        )
        if self._config.ocsp_spike_enabled:
            config_lines.append(
                f"OCSP spike threshold: {self._config.ocsp_spike_threshold}/client/hour"
            )
        sections.append("\n".join(config_lines))

        user_message = "\n\n".join(sections)

        try:
            response = self._llm.complete(LLM_SYSTEM_PROMPT, user_message)  # type: ignore[union-attr]
            if response:
                report.llm_analysis = response
                report.llm_used = True

                # Add an LLM insight finding
                report.findings.append(ReassessmentFinding(
                    category="llm_insight",
                    title="Claude analysis completed",
                    description="See LLM Analysis Summary section for detailed recommendations.",
                    severity="info",
                ))
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
