"""Prompt templates for LLM analysis."""

from typing import Dict, List
from src.models import PIIType, Finding


class PromptTemplates:
    """Prompt templates for different analysis tasks."""

    @staticmethod
    def classify_pii_context(pii_value: str, context: str, detected_type: str) -> str:
        """
        Generate prompt for context-aware PII classification.

        Args:
            pii_value: The detected PII (redacted in practice)
            context: Surrounding text
            detected_type: Initial detection type

        Returns:
            Prompt string
        """
        return f"""You are a privacy compliance expert. Analyze the following PII detection in context.

**Detected Type**: {detected_type}
**Context**: {context}

**Task**:
1. Confirm if this is truly PII or a false positive
2. If it's PII, classify it more precisely
3. Assess the sensitivity level (Critical, High, Medium, Low)
4. Consider the context - is this PII being used appropriately?

Respond in JSON format:
{{
    "is_pii": true/false,
    "type": "EMAIL|PHONE_NUMBER|SSN|etc",
    "sensitivity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}}"""

    @staticmethod
    def analyze_gdpr_compliance(finding: Finding, document_context: str) -> str:
        """
        Generate prompt for GDPR compliance analysis.

        Args:
            finding: PII finding
            document_context: Document type/purpose context

        Returns:
            Prompt string
        """
        return f"""You are a GDPR compliance expert. Analyze this PII finding for regulatory violations.

**PII Type**: {finding.pii_type}
**Location**: {finding.location}
**Context**: {finding.context}
**Document Context**: {document_context}

**Task**:
Identify any GDPR violations related to this PII. Consider:
- Article 5: Principles (lawfulness, fairness, transparency, data minimization)
- Article 6: Lawful basis for processing
- Article 9: Special categories of personal data
- Article 32: Security of processing
- Article 17: Right to erasure
- Article 25: Data protection by design

Respond in JSON format:
{{
    "violations": [
        {{
            "article": "Art. X",
            "article_name": "Full article name",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "explanation": "Why this is a violation",
            "risk": "What could go wrong"
        }}
    ],
    "overall_severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "immediate_actions": ["action 1", "action 2"],
    "reasoning": "Overall assessment"
}}"""

    @staticmethod
    def recommend_anonymization(
        pii_type: str, context: str, usage_purpose: str, sensitivity: str
    ) -> str:
        """
        Generate prompt for anonymization recommendations.

        Args:
            pii_type: Type of PII
            context: How it's being used
            usage_purpose: Business purpose
            sensitivity: Sensitivity level

        Returns:
            Prompt string
        """
        return f"""You are a data privacy engineer. Recommend anonymization strategies for this PII.

**PII Type**: {pii_type}
**Context**: {context}
**Business Purpose**: {usage_purpose}
**Sensitivity**: {sensitivity}

**Available Strategies**:
1. **Redaction**: Complete removal/masking
2. **Pseudonymization**: Replace with consistent token
3. **Tokenization**: Replace with random token (reversible with key)
4. **Generalization**: Replace with category (e.g., age → age range)
5. **Perturbation**: Add noise to numerical data
6. **Encryption**: Encrypt at rest
7. **Hashing**: One-way hash
8. **Partial Masking**: Show only part (e.g., ***-**-1234)

**Task**:
Recommend the most appropriate strategy considering:
- Utility requirements (can you still use the data?)
- Security level needed
- Reversibility requirements
- Performance impact
- Regulatory compliance (GDPR)

Respond in JSON format:
{{
    "recommended_strategy": "strategy name",
    "alternative_strategies": ["strategy 2", "strategy 3"],
    "implementation": "Step-by-step how to implement",
    "trade_offs": "What you lose vs gain",
    "gdpr_compliance": "How this satisfies GDPR",
    "code_example": "Pseudo-code or example"
}}"""

    @staticmethod
    def assess_document_risk(
        findings_summary: Dict, document_type: str, intended_audience: str
    ) -> str:
        """
        Generate prompt for overall document risk assessment.

        Args:
            findings_summary: Summary of all findings
            document_type: Type of document
            intended_audience: Who will see this

        Returns:
            Prompt string
        """
        findings_text = "\n".join(
            [f"- {count}x {pii_type}" for pii_type, count in findings_summary.items()]
        )

        return f"""You are a privacy risk assessor. Evaluate the overall privacy risk of this document.

**Document Type**: {document_type}
**Intended Audience**: {intended_audience}

**PII Detected**:
{findings_text}

**Task**:
Assess the overall privacy risk if this document is:
1. Accidentally leaked
2. Shared with wrong person
3. Stored insecurely
4. Accessed by unauthorized party

Consider:
- Type and quantity of PII
- Document purpose
- Audience expectations
- Potential harm to data subjects
- Regulatory implications

Respond in JSON format:
{{
    "overall_risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
    "risk_score": 0-100,
    "key_concerns": ["concern 1", "concern 2"],
    "potential_impact": {{
        "data_subjects": "Impact on individuals",
        "organization": "Impact on company",
        "regulatory": "Potential fines/penalties"
    }},
    "immediate_actions": ["action 1", "action 2"],
    "remediation_priority": "Priority level and timeline"
}}"""

    @staticmethod
    def explain_finding_to_user(finding: Finding, user_expertise: str = "beginner") -> str:
        """
        Generate prompt for user-friendly explanation.

        Args:
            finding: The finding to explain
            user_expertise: User's technical level

        Returns:
            Prompt string
        """
        return f"""You are explaining privacy issues to a {user_expertise}-level user.

**What was found**: {finding.pii_type}
**Where**: {finding.location}
**Why it matters**: {finding.severity} severity

**Task**:
Explain this finding in simple terms:
1. What is this type of data?
2. Why is it sensitive?
3. What could happen if it leaks?
4. What should they do about it?

Keep the explanation:
- Clear and non-technical (unless user_expertise is "expert")
- Actionable
- Concise (2-3 paragraphs max)
- Focused on practical implications

Respond with plain text explanation."""

    @staticmethod
    def batch_analyze_patterns(findings: List[Finding]) -> str:
        """
        Generate prompt for pattern analysis across multiple findings.

        Args:
            findings: List of findings to analyze

        Returns:
            Prompt string
        """
        findings_summary = {}
        for finding in findings:
            pii_type = finding.pii_type
            findings_summary[pii_type] = findings_summary.get(pii_type, 0) + 1

        summary_text = "\n".join(
            [f"- {pii_type}: {count} occurrences" for pii_type, count in findings_summary.items()]
        )

        return f"""You are a privacy data analyst. Analyze patterns across these PII findings.

**Findings Summary**:
{summary_text}

**Total Findings**: {len(findings)}

**Task**:
Identify patterns and insights:
1. What types of PII appear together? (correlation)
2. Are there systematic issues? (e.g., all emails exposed)
3. What does this reveal about data handling practices?
4. Priority areas for remediation?

Respond in JSON format:
{{
    "patterns": [
        {{
            "pattern": "Description of pattern",
            "occurrences": count,
            "severity": "CRITICAL|HIGH|MEDIUM|LOW"
        }}
    ],
    "systemic_issues": ["issue 1", "issue 2"],
    "recommendations": ["recommendation 1", "recommendation 2"],
    "prioritization": {{
        "critical_first": ["item 1", "item 2"],
        "high_priority": ["item 3", "item 4"],
        "medium_priority": ["item 5"]
    }}
}}"""


class SystemPrompts:
    """System prompts for different analysis modes."""

    PRIVACY_EXPERT = """You are an expert privacy compliance analyst specializing in GDPR, CCPA, and data protection regulations. You provide accurate, actionable advice on privacy issues.

Key principles:
- Accuracy over speed
- Cite specific GDPR articles when relevant
- Consider practical business implications
- Prioritize data subject protection
- Provide concrete, implementable recommendations

Response format: Always use valid JSON when requested. Be concise but complete."""

    DATA_ENGINEER = """You are a data engineering expert specializing in privacy-preserving techniques and secure data handling.

Expertise areas:
- Anonymization and pseudonymization techniques
- Encryption and tokenization
- Privacy-preserving analytics
- Secure data pipeline design
- GDPR-compliant data architectures

Response format: Provide technical but practical solutions. Include code examples when helpful."""

    RISK_ASSESSOR = """You are a privacy risk assessment specialist focusing on realistic threat modeling and impact analysis.

Assessment framework:
- Likelihood of exposure
- Severity of impact
- Regulatory consequences
- Reputational damage
- Mitigation feasibility

Response format: Provide balanced, evidence-based risk assessments with clear severity ratings."""
