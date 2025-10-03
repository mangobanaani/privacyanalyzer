"""GDPR rule engine for compliance checking."""

import yaml
from pathlib import Path
from typing import List, Dict, Optional
from src.models import Finding, ScanResult, Severity
from src.utils import get_logger

logger = get_logger(__name__)


class GDPRRule:
    """Represents a single GDPR rule."""

    def __init__(self, rule_data: dict):
        """
        Initialize GDPR rule.

        Args:
            rule_data: Rule definition from YAML
        """
        self.id = rule_data["id"]
        self.name = rule_data["name"]
        self.article = rule_data["article"]
        self.description = rule_data["description"]
        self.severity = rule_data["severity"]
        self.conditions = rule_data.get("conditions", {})
        self.recommendation = rule_data["recommendation"]

    def matches(self, finding: Finding, scan_result: ScanResult) -> bool:
        """
        Check if this rule applies to a finding.

        Args:
            finding: Finding to check
            scan_result: Overall scan result for context

        Returns:
            True if rule matches
        """
        conditions = self.conditions

        # Check PII types
        if "pii_types" in conditions:
            if finding.pii_type not in conditions["pii_types"]:
                return False

        # Check any PII
        if conditions.get("any_pii", False):
            return True

        # Check source types
        if "source_types" in conditions:
            source_type = scan_result.source_type
            if source_type not in conditions["source_types"]:
                return False

        # Check threshold count
        if "threshold_count" in conditions:
            threshold = conditions["threshold_count"]
            pii_count = scan_result.findings_by_type.get(finding.pii_type, 0)
            if pii_count < threshold:
                return False

        return True


class GDPREngine:
    """GDPR compliance rule engine."""

    def __init__(self, rules_file: Optional[str] = None):
        """
        Initialize GDPR engine.

        Args:
            rules_file: Path to YAML rules file
        """
        if rules_file is None:
            rules_file = Path(__file__).parent.parent.parent / "config" / "rules" / "gdpr_rules.yaml"

        self.rules_file = Path(rules_file)
        self.rules: List[GDPRRule] = []
        self.cookie_rules: List[Dict] = []
        self.web_security_rules: List[Dict] = []
        self.form_rules: List[Dict] = []

        self._load_rules()

    def _load_rules(self) -> None:
        """Load rules from YAML file."""
        try:
            with open(self.rules_file, "r") as f:
                data = yaml.safe_load(f)

            # Load general rules
            for rule_data in data.get("rules", []):
                rule = GDPRRule(rule_data)
                self.rules.append(rule)

            # Load specialized rules
            self.cookie_rules = data.get("cookies", [])
            self.web_security_rules = data.get("web_security", [])
            self.form_rules = data.get("forms", [])

            logger.info(f"Loaded {len(self.rules)} GDPR rules from {self.rules_file}")

        except Exception as e:
            logger.error(f"Failed to load GDPR rules: {e}")
            raise

    def analyze_compliance(self, scan_result: ScanResult) -> Dict:
        """
        Analyze scan results for GDPR compliance.

        Args:
            scan_result: Scan results to analyze

        Returns:
            Compliance analysis dictionary
        """
        violations = []
        compliance_score = 100.0

        # Check each finding against rules
        for finding in scan_result.findings:
            for rule in self.rules:
                if rule.matches(finding, scan_result):
                    violation = {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "article": rule.article,
                        "description": rule.description,
                        "severity": rule.severity,
                        "finding_id": finding.id,
                        "finding_location": finding.location,
                        "recommendation": rule.recommendation,
                    }
                    violations.append(violation)

                    # Deduct from compliance score
                    deduction = self._get_severity_deduction(rule.severity)
                    compliance_score -= deduction

        # Ensure score doesn't go below 0
        compliance_score = max(0.0, compliance_score)

        # Group violations by article
        violations_by_article = self._group_by_article(violations)

        # Determine overall status
        status = self._determine_status(compliance_score, violations)

        return {
            "compliance_score": round(compliance_score, 2),
            "status": status,
            "total_violations": len(violations),
            "violations": violations,
            "violations_by_article": violations_by_article,
            "critical_issues": [v for v in violations if v["severity"] == "critical"],
            "high_issues": [v for v in violations if v["severity"] == "high"],
            "recommendations": self._generate_recommendations(violations),
        }

    def _get_severity_deduction(self, severity: str) -> float:
        """Get score deduction for severity level."""
        deductions = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 1.0}
        return deductions.get(severity, 1.0)

    def _group_by_article(self, violations: List[Dict]) -> Dict[str, List[Dict]]:
        """Group violations by GDPR article."""
        by_article = {}

        for violation in violations:
            article = violation["article"]
            if article not in by_article:
                by_article[article] = []
            by_article[article].append(violation)

        return by_article

    def _determine_status(self, score: float, violations: List[Dict]) -> str:
        """Determine overall compliance status."""
        critical_count = sum(1 for v in violations if v["severity"] == "critical")

        if critical_count > 0:
            return "non_compliant"
        elif score >= 90:
            return "compliant"
        elif score >= 70:
            return "mostly_compliant"
        else:
            return "needs_improvement"

    def _generate_recommendations(self, violations: List[Dict]) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Group by severity
        critical = [v for v in violations if v["severity"] == "critical"]
        high = [v for v in violations if v["severity"] == "high"]

        if critical:
            recommendations.append(
                f"URGENT: Address {len(critical)} critical violations immediately"
            )

        if high:
            recommendations.append(
                f"HIGH PRIORITY: Resolve {len(high)} high-severity issues within 30 days"
            )

        # Get unique recommendations
        unique_recs = {}
        for violation in violations:
            rec = violation["recommendation"]
            if rec not in unique_recs:
                unique_recs[rec] = {
                    "text": rec,
                    "count": 1,
                    "severity": violation["severity"],
                }
            else:
                unique_recs[rec]["count"] += 1

        # Sort by severity and count
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_recs = sorted(
            unique_recs.values(),
            key=lambda x: (severity_order.get(x["severity"], 4), -x["count"]),
        )

        # Add top recommendations
        for rec in sorted_recs[:10]:
            if rec["count"] > 1:
                recommendations.append(f"{rec['text']} (affects {rec['count']} items)")
            else:
                recommendations.append(rec["text"])

        return recommendations

    def get_article_details(self, article: str) -> Optional[Dict]:
        """
        Get details about a GDPR article.

        Args:
            article: Article reference (e.g., "Art. 5")

        Returns:
            Article details or None
        """
        article_info = {
            "Art. 5": {
                "name": "Principles relating to processing of personal data",
                "key_points": [
                    "Lawfulness, fairness, transparency",
                    "Purpose limitation",
                    "Data minimization",
                    "Accuracy",
                    "Storage limitation",
                    "Integrity and confidentiality",
                ],
            },
            "Art. 6": {
                "name": "Lawfulness of processing",
                "key_points": [
                    "Consent",
                    "Contract",
                    "Legal obligation",
                    "Vital interests",
                    "Public task",
                    "Legitimate interests",
                ],
            },
            "Art. 7": {"name": "Conditions for consent", "key_points": ["Freely given", "Specific", "Informed", "Unambiguous"]},
            "Art. 9": {
                "name": "Processing of special categories of personal data",
                "key_points": [
                    "Health data",
                    "Genetic data",
                    "Biometric data",
                    "Racial/ethnic origin",
                    "Political opinions",
                ],
            },
            "Art. 12": {
                "name": "Transparent information, communication and modalities",
                "key_points": ["Concise", "Transparent", "Intelligible", "Easily accessible", "Plain language"],
            },
            "Art. 13": {
                "name": "Information to be provided where personal data are collected",
                "key_points": [
                    "Identity and contact details",
                    "Purposes of processing",
                    "Legal basis",
                    "Recipients",
                    "Retention period",
                    "Rights of data subject",
                ],
            },
            "Art. 15": {
                "name": "Right of access by the data subject",
                "key_points": ["Confirm processing", "Access to data", "Information about processing"],
            },
            "Art. 17": {
                "name": "Right to erasure (right to be forgotten)",
                "key_points": ["Deletion request", "No longer necessary", "Consent withdrawn"],
            },
            "Art. 25": {
                "name": "Data protection by design and by default",
                "key_points": [
                    "Privacy by design",
                    "Pseudonymization",
                    "Data minimization",
                    "Default privacy settings",
                ],
            },
            "Art. 32": {
                "name": "Security of processing",
                "key_points": [
                    "Encryption",
                    "Confidentiality",
                    "Integrity",
                    "Availability",
                    "Resilience",
                    "Regular testing",
                ],
            },
            "Art. 33": {"name": "Notification of a personal data breach", "key_points": ["72-hour notification", "To supervisory authority"]},
            "Art. 35": {
                "name": "Data protection impact assessment",
                "key_points": ["High-risk processing", "Systematic assessment", "Consult DPO"],
            },
        }

        return article_info.get(article)
