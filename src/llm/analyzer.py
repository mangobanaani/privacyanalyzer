"""LLM-powered analysis engine."""

import json
from typing import Dict, Optional, List

from src.llm.claude_client import ClaudeClient
from src.llm.prompts import PromptTemplates, SystemPrompts
from src.models import Finding, PIIType, Severity
from src.utils import get_logger

logger = get_logger(__name__)


class LLMAnalyzer:
    """Provides LLM-powered analysis for PII findings."""

    def __init__(self, claude_client: Optional[ClaudeClient] = None):
        """
        Initialize LLM analyzer.

        Args:
            claude_client: Optional Claude client (creates one if not provided)
        """
        self.client = claude_client or ClaudeClient()

    async def enhance_finding(
        self, finding: Finding, context: str = "", use_llm: bool = True
    ) -> Finding:
        """
        Enhance a finding with LLM analysis.

        Args:
            finding: Initial finding from detector
            context: Additional document context
            use_llm: Whether to use LLM (can disable for testing)

        Returns:
            Enhanced finding with LLM insights
        """
        if not use_llm:
            return finding

        try:
            # Context-aware classification
            classification = await self._classify_with_context(finding)

            # Update finding based on LLM analysis
            if classification:
                finding.confidence = max(
                    finding.confidence, classification.get("confidence", finding.confidence)
                )

                # Update severity if LLM suggests different
                llm_severity = classification.get("sensitivity", "").upper()
                if llm_severity in [s.value for s in Severity]:
                    finding.severity = Severity(llm_severity.lower())

            # GDPR analysis
            gdpr_analysis = await self._analyze_gdpr_compliance(finding, context)

            if gdpr_analysis:
                finding.gdpr_articles = [
                    v["article"] for v in gdpr_analysis.get("violations", [])
                ]
                finding.gdpr_reasoning = gdpr_analysis.get("reasoning", "")

            # Anonymization recommendation
            anon_rec = await self._recommend_anonymization(finding)

            if anon_rec:
                finding.anonymization_strategy = anon_rec.get("recommended_strategy", "")
                # Update recommendation with LLM insights
                implementation = anon_rec.get("implementation", "")
                if implementation:
                    finding.recommendation = f"{finding.recommendation}\n\nSuggested approach: {implementation}"

        except Exception as e:
            logger.error(f"LLM enhancement failed: {e}")
            # Don't fail the whole finding, just log and continue

        return finding

    async def _classify_with_context(self, finding: Finding) -> Optional[Dict]:
        """
        Use LLM to refine PII classification based on context.

        Args:
            finding: Finding to classify

        Returns:
            Classification result dict
        """
        try:
            prompt = PromptTemplates.classify_pii_context(
                pii_value="[REDACTED]",  # Never send actual PII to LLM
                context=finding.context,
                detected_type=finding.pii_type,
            )

            response = await self.client.complete(
                prompt=prompt,
                max_tokens=500,
                temperature=0.0,
                system=SystemPrompts.PRIVACY_EXPERT,
            )

            # Parse JSON response
            result = self._parse_json_response(response)
            return result

        except Exception as e:
            logger.warning(f"Context classification failed: {e}")
            return None

    async def _analyze_gdpr_compliance(
        self, finding: Finding, document_context: str
    ) -> Optional[Dict]:
        """
        Analyze GDPR compliance using LLM.

        Args:
            finding: Finding to analyze
            document_context: Document context

        Returns:
            GDPR analysis dict
        """
        try:
            prompt = PromptTemplates.analyze_gdpr_compliance(finding, document_context)

            response = await self.client.complete(
                prompt=prompt,
                max_tokens=1000,
                temperature=0.0,
                system=SystemPrompts.PRIVACY_EXPERT,
            )

            result = self._parse_json_response(response)
            return result

        except Exception as e:
            logger.warning(f"GDPR analysis failed: {e}")
            return None

    async def _recommend_anonymization(self, finding: Finding) -> Optional[Dict]:
        """
        Get anonymization recommendations from LLM.

        Args:
            finding: Finding to get recommendations for

        Returns:
            Anonymization recommendation dict
        """
        try:
            prompt = PromptTemplates.recommend_anonymization(
                pii_type=finding.pii_type,
                context=finding.context,
                usage_purpose="Unknown",  # Could be enhanced with document metadata
                sensitivity=finding.severity,
            )

            response = await self.client.complete(
                prompt=prompt,
                max_tokens=1000,
                temperature=0.0,
                system=SystemPrompts.DATA_ENGINEER,
            )

            result = self._parse_json_response(response)
            return result

        except Exception as e:
            logger.warning(f"Anonymization recommendation failed: {e}")
            return None

    async def assess_document_risk(
        self, findings: List[Finding], document_type: str, intended_audience: str = "internal"
    ) -> Optional[Dict]:
        """
        Assess overall document privacy risk.

        Args:
            findings: All findings for the document
            document_type: Type of document
            intended_audience: Who will see this

        Returns:
            Risk assessment dict
        """
        try:
            # Summarize findings
            summary = {}
            for finding in findings:
                pii_type = finding.pii_type
                summary[pii_type] = summary.get(pii_type, 0) + 1

            prompt = PromptTemplates.assess_document_risk(
                findings_summary=summary,
                document_type=document_type,
                intended_audience=intended_audience,
            )

            response = await self.client.complete(
                prompt=prompt,
                max_tokens=1500,
                temperature=0.0,
                system=SystemPrompts.RISK_ASSESSOR,
            )

            result = self._parse_json_response(response)
            return result

        except Exception as e:
            logger.error(f"Document risk assessment failed: {e}")
            return None

    async def analyze_patterns(self, findings: List[Finding]) -> Optional[Dict]:
        """
        Analyze patterns across multiple findings.

        Args:
            findings: List of findings to analyze

        Returns:
            Pattern analysis dict
        """
        try:
            prompt = PromptTemplates.batch_analyze_patterns(findings)

            response = await self.client.complete(
                prompt=prompt,
                max_tokens=1500,
                temperature=0.0,
                system=SystemPrompts.PRIVACY_EXPERT,
            )

            result = self._parse_json_response(response)
            return result

        except Exception as e:
            logger.error(f"Pattern analysis failed: {e}")
            return None

    async def explain_to_user(
        self, finding: Finding, user_expertise: str = "beginner"
    ) -> Optional[str]:
        """
        Generate user-friendly explanation of finding.

        Args:
            finding: Finding to explain
            user_expertise: User's technical level

        Returns:
            Plain text explanation
        """
        try:
            prompt = PromptTemplates.explain_finding_to_user(finding, user_expertise)

            response = await self.client.complete(
                prompt=prompt, max_tokens=500, temperature=0.3  # Slightly higher for readability
            )

            return response.strip()

        except Exception as e:
            logger.error(f"User explanation failed: {e}")
            return None

    def _parse_json_response(self, response: str) -> Optional[Dict]:
        """
        Parse JSON from LLM response.

        Args:
            response: Raw LLM response

        Returns:
            Parsed dict or None
        """
        try:
            # Try to extract JSON from markdown code blocks if present
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                json_str = response[start:end].strip()
            elif "```" in response:
                start = response.find("```") + 3
                end = response.find("```", start)
                json_str = response[start:end].strip()
            else:
                json_str = response.strip()

            return json.loads(json_str)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            logger.debug(f"Response was: {response[:200]}")
            return None
