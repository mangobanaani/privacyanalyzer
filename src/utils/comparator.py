"""Scan result comparison utilities."""

from typing import Dict, List, Set
from datetime import datetime
from src.models import ScanResult, Finding


class ScanComparator:
    """Compare two scan results to identify changes."""

    def compare(self, baseline: ScanResult, current: ScanResult) -> Dict:
        """
        Compare two scan results.

        Args:
            baseline: Previous scan result
            current: Current scan result

        Returns:
            Comparison dictionary with changes
        """
        comparison = {
            "baseline": {
                "scan_id": baseline.scan_id,
                "timestamp": baseline.start_time.isoformat() if baseline.start_time else None,
                "total_findings": baseline.total_findings,
            },
            "current": {
                "scan_id": current.scan_id,
                "timestamp": current.start_time.isoformat() if current.start_time else None,
                "total_findings": current.total_findings,
            },
            "changes": {
                "new_findings": [],
                "resolved_findings": [],
                "modified_findings": [],
                "unchanged_findings": [],
            },
            "summary": {
                "new_count": 0,
                "resolved_count": 0,
                "modified_count": 0,
                "unchanged_count": 0,
                "net_change": 0,
            },
        }

        # Create finding signatures for comparison
        baseline_findings = {self._create_signature(f): f for f in baseline.findings}
        current_findings = {self._create_signature(f): f for f in current.findings}

        baseline_sigs = set(baseline_findings.keys())
        current_sigs = set(current_findings.keys())

        # Identify new findings
        new_sigs = current_sigs - baseline_sigs
        for sig in new_sigs:
            finding = current_findings[sig]
            comparison["changes"]["new_findings"].append({
                "pii_type": finding.pii_type,
                "location": finding.location,
                "severity": finding.severity,
                "confidence": finding.confidence,
            })

        # Identify resolved findings
        resolved_sigs = baseline_sigs - current_sigs
        for sig in resolved_sigs:
            finding = baseline_findings[sig]
            comparison["changes"]["resolved_findings"].append({
                "pii_type": finding.pii_type,
                "location": finding.location,
                "severity": finding.severity,
            })

        # Identify unchanged findings
        unchanged_sigs = baseline_sigs & current_sigs
        for sig in unchanged_sigs:
            baseline_finding = baseline_findings[sig]
            current_finding = current_findings[sig]

            # Check if confidence or severity changed
            if (baseline_finding.confidence != current_finding.confidence or
                baseline_finding.severity != current_finding.severity):
                comparison["changes"]["modified_findings"].append({
                    "pii_type": current_finding.pii_type,
                    "location": current_finding.location,
                    "baseline_severity": baseline_finding.severity,
                    "current_severity": current_finding.severity,
                    "baseline_confidence": baseline_finding.confidence,
                    "current_confidence": current_finding.confidence,
                })
            else:
                comparison["changes"]["unchanged_findings"].append({
                    "pii_type": current_finding.pii_type,
                    "location": current_finding.location,
                    "severity": current_finding.severity,
                })

        # Update summary
        comparison["summary"]["new_count"] = len(new_sigs)
        comparison["summary"]["resolved_count"] = len(resolved_sigs)
        comparison["summary"]["modified_count"] = len(comparison["changes"]["modified_findings"])
        comparison["summary"]["unchanged_count"] = len(comparison["changes"]["unchanged_findings"])
        comparison["summary"]["net_change"] = len(new_sigs) - len(resolved_sigs)

        # Calculate trend
        if comparison["summary"]["net_change"] > 0:
            comparison["summary"]["trend"] = "worse"
        elif comparison["summary"]["net_change"] < 0:
            comparison["summary"]["trend"] = "better"
        else:
            comparison["summary"]["trend"] = "stable"

        return comparison

    def _create_signature(self, finding: Finding) -> str:
        """
        Create a unique signature for a finding.

        Args:
            finding: Finding to create signature for

        Returns:
            Signature string
        """
        # Use location and PII type as signature
        # This allows matching the same finding across scans
        return f"{finding.location}:{finding.pii_type}:{finding.content[:50]}"

    def compare_severity_distribution(self, baseline: ScanResult, current: ScanResult) -> Dict:
        """
        Compare severity distribution between scans.

        Args:
            baseline: Previous scan result
            current: Current scan result

        Returns:
            Severity comparison
        """
        comparison = {
            "baseline": baseline.findings_by_severity,
            "current": current.findings_by_severity,
            "changes": {},
        }

        all_severities = set(baseline.findings_by_severity.keys()) | set(
            current.findings_by_severity.keys()
        )

        for severity in all_severities:
            baseline_count = baseline.findings_by_severity.get(severity, 0)
            current_count = current.findings_by_severity.get(severity, 0)
            change = current_count - baseline_count

            comparison["changes"][severity] = {
                "baseline": baseline_count,
                "current": current_count,
                "change": change,
                "percent_change": (
                    (change / baseline_count * 100) if baseline_count > 0 else 0
                ),
            }

        return comparison

    def compare_pii_types(self, baseline: ScanResult, current: ScanResult) -> Dict:
        """
        Compare PII type distribution between scans.

        Args:
            baseline: Previous scan result
            current: Current scan result

        Returns:
            PII type comparison
        """
        comparison = {
            "baseline": baseline.findings_by_type,
            "current": current.findings_by_type,
            "new_types": [],
            "removed_types": [],
            "changed_types": {},
        }

        baseline_types = set(baseline.findings_by_type.keys())
        current_types = set(current.findings_by_type.keys())

        # New PII types detected
        new_types = current_types - baseline_types
        comparison["new_types"] = list(new_types)

        # PII types no longer detected
        removed_types = baseline_types - current_types
        comparison["removed_types"] = list(removed_types)

        # Changed counts for existing types
        common_types = baseline_types & current_types
        for pii_type in common_types:
            baseline_count = baseline.findings_by_type[pii_type]
            current_count = current.findings_by_type[pii_type]

            if baseline_count != current_count:
                comparison["changed_types"][pii_type] = {
                    "baseline": baseline_count,
                    "current": current_count,
                    "change": current_count - baseline_count,
                }

        return comparison

    def generate_comparison_report(self, baseline: ScanResult, current: ScanResult) -> str:
        """
        Generate a text report of the comparison.

        Args:
            baseline: Previous scan result
            current: Current scan result

        Returns:
            Formatted comparison report
        """
        comparison = self.compare(baseline, current)

        report = []
        report.append("=" * 80)
        report.append("SCAN COMPARISON REPORT")
        report.append("=" * 80)
        report.append("")

        # Baseline info
        report.append(f"Baseline Scan: {comparison['baseline']['scan_id']}")
        report.append(f"  Timestamp: {comparison['baseline']['timestamp']}")
        report.append(f"  Total Findings: {comparison['baseline']['total_findings']}")
        report.append("")

        # Current info
        report.append(f"Current Scan: {comparison['current']['scan_id']}")
        report.append(f"  Timestamp: {comparison['current']['timestamp']}")
        report.append(f"  Total Findings: {comparison['current']['total_findings']}")
        report.append("")

        # Summary
        report.append("SUMMARY")
        report.append("-" * 80)
        summary = comparison["summary"]
        report.append(f"  New Findings:       {summary['new_count']}")
        report.append(f"  Resolved Findings:  {summary['resolved_count']}")
        report.append(f"  Modified Findings:  {summary['modified_count']}")
        report.append(f"  Unchanged Findings: {summary['unchanged_count']}")
        report.append(f"  Net Change:         {summary['net_change']:+d}")
        report.append(f"  Trend:              {summary['trend'].upper()}")
        report.append("")

        # New findings
        if comparison["changes"]["new_findings"]:
            report.append("NEW FINDINGS")
            report.append("-" * 80)
            for finding in comparison["changes"]["new_findings"]:
                report.append(
                    f"  [{finding['severity'].upper()}] {finding['pii_type']} "
                    f"at {finding['location']} (confidence: {finding['confidence']:.2f})"
                )
            report.append("")

        # Resolved findings
        if comparison["changes"]["resolved_findings"]:
            report.append("RESOLVED FINDINGS")
            report.append("-" * 80)
            for finding in comparison["changes"]["resolved_findings"]:
                report.append(
                    f"  [{finding['severity'].upper()}] {finding['pii_type']} "
                    f"at {finding['location']}"
                )
            report.append("")

        # Modified findings
        if comparison["changes"]["modified_findings"]:
            report.append("MODIFIED FINDINGS")
            report.append("-" * 80)
            for finding in comparison["changes"]["modified_findings"]:
                report.append(f"  {finding['pii_type']} at {finding['location']}")
                report.append(
                    f"    Severity: {finding['baseline_severity']} -> {finding['current_severity']}"
                )
                report.append(
                    f"    Confidence: {finding['baseline_confidence']:.2f} -> "
                    f"{finding['current_confidence']:.2f}"
                )
            report.append("")

        report.append("=" * 80)

        return "\n".join(report)
