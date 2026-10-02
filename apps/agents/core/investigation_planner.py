"""
InvestigationPlanner: Evidence-Driven, Adaptive Investigation Planner.
Implements RuleBasedPlanner, LLMPlanner, and HybridPlanner.
Dynamically maps Evidence -> Unresolved Questions -> Information-Gain Tool Selection -> Replanning.
Does NOT use rigid pre-determined sequences or hardcoded artifact-to-tool shortcuts.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

from apps.agents.core.investigation_state import (
    InvestigationState,
    Evidence,
    Hypothesis,
    Question,
    PlannerDecision,
    ToolExecution,
    Verdict
)
from packages.schemas.python.models import ToolDefinition

logger = logging.getLogger("InvestigationPlanner")


class InvestigationPlanner(ABC):
    """Abstract interface for evidence-driven investigation planners."""
    
    @abstractmethod
    def propose_next_action(
        self,
        state: InvestigationState,
        available_tools: List[ToolDefinition],
        permissions: List[str]
    ) -> PlannerDecision:
        """
        Evaluates current evidence, active hypotheses, and unresolved questions
        to select the next optimal tool execution or decide to stop.
        """
        pass


class RuleBasedPlanner(InvestigationPlanner):
    """
    Evidence & Information-Gain Driven Planner for Offline / Deterministic environments.
    Dynamically reasons over:
    - Evidence dependencies & preconditions
    - Active hypotheses (H-001 to H-005)
    - Priority-weighted unresolved questions
    - Negative evidence (e.g. no attachments -> skip attachment analyzer)
    - Tool costs and expected information gain
    - Early stopping when confidence is sufficient
    """

    def propose_next_action(
        self,
        state: InvestigationState,
        available_tools: List[ToolDefinition],
        permissions: List[str]
    ) -> PlannerDecision:
        # 1. Update questions & hypotheses based on latest state
        self._update_questions_and_hypotheses(state)
        
        executed_tool_names = {t.tool_name for t in state.executed_tools if t.status == "COMPLETED"}
        unresolved_questions = [q for q in state.questions.values() if q.status == "UNRESOLVED"]
        
        # 2. Check early stopping conditions
        if state.remaining_budget_steps <= 0:
            return PlannerDecision(
                action="STOP",
                engine_type="RULE_ENGINE",
                rationale="Investigation budget exhausted.",
                stop_reason="BUDGET_EXHAUSTED",
                confidence_before=self._calculate_overall_confidence(state),
                confidence_after=self._calculate_overall_confidence(state)
            )

        if not unresolved_questions:
            return PlannerDecision(
                action="STOP",
                engine_type="RULE_ENGINE",
                rationale="All security questions have been conclusively resolved.",
                stop_reason="SUFFICIENT_EVIDENCE",
                confidence_before=self._calculate_overall_confidence(state),
                confidence_after=self._calculate_overall_confidence(state)
            )

        # Conclusive evidence early stop check
        # e.g. If malicious URL verified by threat intel and sender spoofing confirmed, high confidence reached
        current_conf = self._calculate_overall_confidence(state)
        if current_conf >= 0.92 and len(executed_tool_names) >= 2:
            return PlannerDecision(
                action="STOP",
                engine_type="RULE_ENGINE",
                rationale=f"High confidence ({current_conf:.2f}) reached with sufficient evidence. Concluding investigation early.",
                stop_reason="SUFFICIENT_EVIDENCE",
                confidence_before=current_conf,
                confidence_after=current_conf
            )

        # 3. Evaluate candidate tools by Information Gain
        candidates = []
        for tool in available_tools:
            if tool.name in executed_tool_names:
                continue  # Do not re-run already executed tool
                
            # Check permissions
            if tool.required_permission and tool.required_permission not in permissions and "admin" not in permissions:
                continue
                
            # Check negative evidence constraints
            if not self._check_preconditions(tool.name, state):
                continue
                
            # Calculate Information Gain
            info_gain, addressed_q_ids, rationale = self._calculate_information_gain(tool.name, state)
            if info_gain > 0.0:
                candidates.append({
                    "tool": tool,
                    "info_gain": info_gain,
                    "addressed_questions": addressed_q_ids,
                    "rationale": rationale,
                    "cost": tool.cost
                })

        # 4. If no candidate has positive information gain, stop
        if not candidates:
            return PlannerDecision(
                action="STOP",
                engine_type="RULE_ENGINE",
                rationale="No remaining available tools address unresolved questions.",
                stop_reason="NO_USEFUL_TOOLS",
                confidence_before=current_conf,
                confidence_after=current_conf
            )

        # Sort candidates by information gain (descending), breaking ties by lower cost
        candidates.sort(key=lambda c: (c["info_gain"], -c["cost"]), reverse=True)
        best = candidates[0]

        return PlannerDecision(
            action="RUN_TOOL",
            engine_type="RULE_ENGINE",
            tool_name=best["tool"].name,
            rationale=best["rationale"],
            addresses_questions=best["addressed_questions"],
            expected_information_gain=best["info_gain"],
            estimated_cost=best["cost"],
            confidence_before=current_conf,
            confidence_after=min(0.99, current_conf + best["info_gain"] * 0.2)
        )

    def _update_questions_and_hypotheses(self, state: InvestigationState):
        """Dynamically formulates/resolves questions and hypotheses based on current evidence."""
        has_mime = any(getattr(e, "evidence_type", getattr(e, "type", "")) == "MIME_HEADER" for e in state.evidence.values())
        has_auth = any(getattr(e, "evidence_type", getattr(e, "type", "")) == "AUTHENTICATION" for e in state.evidence.values())
        has_unicode = any(getattr(e, "evidence_type", getattr(e, "type", "")) == "UNICODE_ANOMALY" for e in state.evidence.values())
        has_url = any(getattr(e, "evidence_type", getattr(e, "type", "")) in ["URL_NORMALIZED", "URL_REPUTATION"] for e in state.evidence.values())
        has_moniker = any(getattr(e, "evidence_type", getattr(e, "type", "")) == "MONIKER_URI" for e in state.evidence.values())
        has_att = any(getattr(e, "evidence_type", getattr(e, "type", "")) in ["ATTACHMENT_PE", "ATTACHMENT_MACRO", "ATTACHMENT_ANALYSIS"] for e in state.evidence.values())

        # Ensure base Hypotheses exist
        if "H-001" not in state.hypotheses:
            state.hypotheses["H-001"] = Hypothesis(
                id="H-001",
                statement="Sender identity authenticity is legitimate and aligned.",
                category="IMPERSONATION",
                confidence=0.5
            )
        if "H-002" not in state.hypotheses:
            state.hypotheses["H-002"] = Hypothesis(
                id="H-002",
                statement="Body or headers utilize hidden Unicode tags/RTLO for filter evasion.",
                category="CREDENTIAL_PHISHING",
                confidence=0.5
            )
        if "H-003" not in state.hypotheses:
            state.hypotheses["H-003"] = Hypothesis(
                id="H-003",
                statement="Hyperlink targets malicious infrastructure or phishing portal.",
                category="MALICIOUS_REDIRECT",
                confidence=0.5
            )
        if "H-004" not in state.hypotheses:
            state.hypotheses["H-004"] = Hypothesis(
                id="H-004",
                statement="URI scheme attempts zero-click client rendering or MonikerLink exploit.",
                category="EXPLOIT_ATTEMPT",
                confidence=0.5
            )
        if "H-005" not in state.hypotheses:
            state.hypotheses["H-005"] = Hypothesis(
                id="H-005",
                statement="Attachment payload contains executable code, PE binary, or MOTW bypass container.",
                category="ATTACHMENT_EXECUTION",
                confidence=0.5
            )

        # Ensure Questions exist & resolve them based on evidence
        # Q-01: MIME Header & Auth
        if "Q-01" not in state.questions:
            state.questions["Q-01"] = Question(
                id="Q-01",
                text="Is the sender identity authentic and SPF/DKIM aligned?",
                priority=1.0,
                category="AUTHENTICATION",
                related_hypothesis_id="H-001"
            )
        elif has_auth:
            state.questions["Q-01"].status = "RESOLVED"
            auth_ev = next((e for e in state.evidence.values() if getattr(e, "evidence_type", getattr(e, "type", "")) == "AUTHENTICATION"), None)
            if auth_ev:
                state.questions["Q-01"].resolution_evidence_id = auth_ev.id
                if "FAIL" in auth_ev.value.upper() or "SPOOF" in auth_ev.value.upper():
                    state.hypotheses["H-001"].status = "CONTRADICTED"
                    state.hypotheses["H-001"].confidence = 0.1
                else:
                    state.hypotheses["H-001"].status = "SUPPORTED"
                    state.hypotheses["H-001"].confidence = 0.95

        # Q-02: Unicode Anomaly
        if "Q-02" not in state.questions:
            state.questions["Q-02"] = Question(
                id="Q-02",
                text="Does the subject, header, or body contain hidden Unicode tags or RTLO override characters?",
                priority=0.9,
                category="UNICODE",
                related_hypothesis_id="H-002"
            )
        elif has_unicode or any(t.tool_name == "UnicodeAnalyzer" for t in state.executed_tools):
            state.questions["Q-02"].status = "RESOLVED"
            uni_ev = next((e for e in state.evidence.values() if getattr(e, "evidence_type", getattr(e, "type", "")) == "UNICODE_ANOMALY"), None)
            if uni_ev:
                state.questions["Q-02"].resolution_evidence_id = uni_ev.id
                state.hypotheses["H-002"].status = "SUPPORTED"
                state.hypotheses["H-002"].confidence = 0.9
            else:
                state.hypotheses["H-002"].status = "CLOSED"
                state.hypotheses["H-002"].confidence = 0.05

        # Q-03: URL Threat Reputation & Behavioral Sandbox
        # Precondition: URL artifact exists
        has_url_artifact = any(a.artifact_type == "URL_STRING" for a in state.artifacts)
        if has_url_artifact:
            target_url = next((str(a.raw_data) for a in state.artifacts if a.artifact_type == "URL_STRING"), "")
            if "Q-03" not in state.questions:
                state.questions["Q-03"] = Question(
                    id="Q-03",
                    text="Is the destination URL associated with known malicious threat infrastructure?",
                    priority=0.95,
                    category="REPUTATION",
                    related_hypothesis_id="H-003"
                )
            else:
                ti_ran = any(t.tool_name in ["threat_intel_lookup", "ThreatIntelFeeds"] for t in state.executed_tools)
                sandbox_ran = any(t.tool_name in ["url_sandbox_detonation", "UrlSandboxRunner"] for t in state.executed_tools)

                # Explicit semantic lookup: Q-03 strictly requires URL_REPUTATION or BEHAVIORAL_SANDBOX.
                # It MUST NOT match URL_NORMALIZED or generic URL artifacts.
                # Evidence MUST be strictly scoped to target_url.
                rep_ev = None
                if hasattr(state, "get_latest_evidence"):
                    rep_ev = state.get_latest_evidence("URL_REPUTATION", subject=target_url)
                else:
                    for e in reversed(list(state.evidence.values())):
                        if getattr(e, "evidence_type", getattr(e, "type", "")) == "URL_REPUTATION":
                            e_subj = getattr(e, "subject", None) or (e.metadata.get("subject") if hasattr(e, "metadata") else None)
                            if e_subj is None or e_subj == target_url:
                                rep_ev = e
                                break


                # Inspect structured metadata from ThreatIntelFeeds
                is_rep_malicious = False
                if rep_ev:
                    is_rep_malicious = (
                        rep_ev.metadata.get("is_malicious") is True
                        or rep_ev.metadata.get("reputation") == "MALICIOUS"
                        or "MALICIOUS" in rep_ev.value.upper()
                    )

                if is_rep_malicious:
                    # Threat intelligence conclusively flagged URL as malicious.
                    # Resolve Q-03 immediately; sandbox execution is not required.
                    state.questions["Q-03"].status = "RESOLVED"
                    state.questions["Q-03"].resolution_evidence_id = rep_ev.id
                    state.hypotheses["H-003"].status = "SUPPORTED"
                    state.hypotheses["H-003"].confidence = 0.95
                elif sandbox_ran:
                    # Sandbox execution completed: evaluate BEHAVIORAL_SANDBOX evidence
                    sb_ev = None
                    if hasattr(state, "get_latest_evidence"):
                        sb_ev = state.get_latest_evidence("BEHAVIORAL_SANDBOX", subject=target_url)
                    else:
                        for e in reversed(list(state.evidence.values())):
                            if getattr(e, "evidence_type", getattr(e, "type", "")) == "BEHAVIORAL_SANDBOX":
                                e_subj = getattr(e, "subject", None) or (e.metadata.get("subject") if hasattr(e, "metadata") else None)
                                if e_subj is None or e_subj == target_url:
                                    sb_ev = e
                                    break

                    state.questions["Q-03"].status = "RESOLVED"
                    if sb_ev:
                        state.questions["Q-03"].resolution_evidence_id = sb_ev.id
                        is_sb_anom = (
                            sb_ev.metadata.get("is_benign") is False
                            or sb_ev.metadata.get("risk_score", 0) >= 50
                            or len(sb_ev.metadata.get("rendering_anomalies", [])) > 0
                            or any(k in sb_ev.value.upper() for k in ["FORCED", "ANOMALY", "MALICIOUS", "CALLOUT"])
                        )
                        if is_sb_anom:
                            state.hypotheses["H-003"].status = "SUPPORTED"
                            state.hypotheses["H-003"].confidence = 0.90
                        else:
                            state.hypotheses["H-003"].status = "CLOSED"
                            state.hypotheses["H-003"].confidence = 0.15
                    else:
                        state.hypotheses["H-003"].status = "CLOSED"
                        state.hypotheses["H-003"].confidence = 0.15
                elif ti_ran:
                    # Counterfactual branch: Threat intelligence ran but returned UNKNOWN/CLEAN.
                    # Q-03 remains UNRESOLVED, compelling the planner to evaluate remaining candidates
                    # and dynamically branch to UrlSandboxRunner for deep behavioral analysis!
                    state.questions["Q-03"].status = "UNRESOLVED"
        elif "Q-03" in state.questions:
            # Negative evidence: no URLs exist, so Q-03 is not applicable / resolved
            state.questions["Q-03"].status = "RESOLVED"
            state.hypotheses["H-003"].status = "CLOSED"
            state.hypotheses["H-003"].confidence = 0.0


        # Q-04: Moniker & Non-Network Schemes
        has_moniker_artifact = any(
            a.artifact_type == "URL_STRING" and any(scheme in str(a.raw_data).lower() for scheme in ["file:", "search:", "search-ms:", "moniker:"])
            for a in state.artifacts
        )
        if has_moniker_artifact:
            if "Q-04" not in state.questions:
                state.questions["Q-04"] = Question(
                    id="Q-04",
                    text="Does the URI scheme trigger zero-click client-side rendering vulnerability or NTLM hash leakage?",
                    priority=1.0,
                    category="EXPLOIT",
                    related_hypothesis_id="H-004"
                )
            elif has_moniker or any(t.tool_name in ["dns_spf_dmarc_recon", "threat_intel_lookup", "ThreatIntelFeeds"] for t in state.executed_tools):
                state.questions["Q-04"].status = "RESOLVED"
                mon_ev = next((e for e in state.evidence.values() if getattr(e, "evidence_type", getattr(e, "type", "")) == "MONIKER_URI"), None)
                if mon_ev:
                    state.questions["Q-04"].resolution_evidence_id = mon_ev.id
                    state.hypotheses["H-004"].status = "SUPPORTED"
                    state.hypotheses["H-004"].confidence = 0.95
        elif "Q-04" in state.questions:
            state.questions["Q-04"].status = "RESOLVED"
            state.hypotheses["H-004"].status = "CLOSED"
            state.hypotheses["H-004"].confidence = 0.0

        # Q-05: Attachment Inspection
        has_att_artifact = any(a.artifact_type == "ATTACHMENT_PAYLOAD" for a in state.artifacts)
        if has_att_artifact:
            if "Q-05" not in state.questions:
                state.questions["Q-05"] = Question(
                    id="Q-05",
                    text="Does the attachment payload contain executable binary code, OLE macros, or MOTW evasion containers?",
                    priority=0.95,
                    category="ATTACHMENT",
                    related_hypothesis_id="H-005"
                )
            elif has_att or any(t.tool_name in ["inspect_attachment", "AttachmentAnalyzer"] for t in state.executed_tools):
                state.questions["Q-05"].status = "RESOLVED"
                att_ev = next((e for e in state.evidence.values() if getattr(e, "evidence_type", getattr(e, "type", "")) in ["ATTACHMENT_PE", "ATTACHMENT_MACRO", "ATTACHMENT_ANALYSIS"]), None)
                if att_ev and any(k in att_ev.value.upper() for k in ["MALICIOUS", "SUSPICIOUS", "EVASION", "HIGH"]):
                    state.hypotheses["H-005"].status = "SUPPORTED"
                    state.hypotheses["H-005"].confidence = 0.9
        elif "Q-05" in state.questions:
            state.questions["Q-05"].status = "RESOLVED"
            state.hypotheses["H-005"].status = "CLOSED"
            state.hypotheses["H-005"].confidence = 0.0

    def _check_preconditions(self, tool_name: str, state: InvestigationState) -> bool:
        """Enforces negative evidence constraints so unnecessary tools are never selected."""
        has_url_artifact = any(a.artifact_type == "URL_STRING" for a in state.artifacts)
        has_att_artifact = any(a.artifact_type == "ATTACHMENT_PAYLOAD" for a in state.artifacts)
        has_text_artifact = any(a.artifact_type in ["BODY_HTML", "BODY_PLAIN", "MIME_HEADER"] for a in state.artifacts)

        if tool_name in ["threat_intel_lookup", "ThreatIntelFeeds", "url_sandbox_detonation", "UrlSandboxRunner"] and not has_url_artifact:
            return False  # Negative evidence: No URL -> Skip URL tools

        if tool_name in ["inspect_attachment", "AttachmentAnalyzer"] and not has_att_artifact:
            return False  # Negative evidence: No attachment -> Skip attachment tools

        if tool_name == "UnicodeAnalyzer" and not has_text_artifact:
            return False

        return True

    def _calculate_information_gain(self, tool_name: str, state: InvestigationState) -> tuple[float, List[str], str]:
        """Calculates information gain, addressing questions, and rationale for a tool candidate."""
        unresolved = {q.id: q for q in state.questions.values() if q.status == "UNRESOLVED"}
        
        if tool_name == "UnicodeAnalyzer":
            if "Q-02" in unresolved:
                q = unresolved["Q-02"]
                return 0.85, [q.id], f"UnicodeAnalyzer addresses highest priority question '{q.text}' to detect zero-width/RTLO evasion."
            return 0.1, [], "UnicodeAnalyzer provides baseline text codepoint inspection."

        if tool_name == "threat_intel_lookup":
            return 0.0, [], "Preferring ThreatIntelFeeds alias"

        if tool_name == "url_sandbox_detonation":
            return 0.0, [], "Preferring UrlSandboxRunner alias"

        if tool_name == "inspect_attachment":
            return 0.0, [], "Preferring AttachmentAnalyzer alias"

        if tool_name == "ThreatIntelFeeds":
            addressed = []
            if "Q-03" in unresolved:
                addressed.append("Q-03")
            if "Q-04" in unresolved:
                addressed.append("Q-04")
            if addressed:
                gain = 0.90 if len(addressed) > 1 else 0.75
                return gain, addressed, f"ThreatIntelFeeds queries reputation feeds without local execution cost to answer {', '.join(addressed)}."
            return 0.0, [], "Threat intel lookup offers low gain since URL/domain questions are already resolved."

        if tool_name == "UrlSandboxRunner":
            if "Q-03" in unresolved:
                # If threat intel already ran and was inconclusive, sandbox has highest gain!
                threat_ran = any(t.tool_name in ["threat_intel_lookup", "ThreatIntelFeeds"] for t in state.executed_tools)
                gain = 0.88 if threat_ran else 0.65
                return gain, ["Q-03"], "UrlSandboxRunner performs DOM/JS isolation rendering to trace multi-hop redirects and login forms."
            return 0.0, [], "Sandbox detonation unnecessary as URL reputation is already resolved."

        if tool_name == "AttachmentAnalyzer":
            if "Q-05" in unresolved:
                q = unresolved["Q-05"]
                return 0.92, [q.id], f"AttachmentAnalyzer performs safe static analysis to inspect container structure, PE headers, and MOTW bypass."
            return 0.0, [], "Attachment inspection unnecessary as no unresolved attachment questions remain."

        if tool_name == "dns_spf_dmarc_recon":
            if "Q-01" in unresolved:
                q = unresolved["Q-01"]
                return 0.80, [q.id], f"dns_spf_dmarc_recon verifies DNS SPF/DMARC records to evaluate sender domain spoofing."
            return 0.0, [], "DNS recon unnecessary as sender authentication is resolved."

        if tool_name == "query_sender_history":
            if "Q-01" in unresolved:
                return 0.50, ["Q-01"], "query_sender_history checks historical communication baseline for sender anomaly detection."
            return 0.20, [], "Query sender history provides contextual communication baseline."

        # Default low gain for generic actions
        return 0.10, [], f"Executing tool '{tool_name}' for general forensic telemetry."

    def _calculate_overall_confidence(self, state: InvestigationState) -> float:
        """Computes aggregate confidence score based on supported hypotheses and resolved questions."""
        if not state.questions:
            return 0.5
        resolved_count = sum(1 for q in state.questions.values() if q.status == "RESOLVED")
        ratio = resolved_count / len(state.questions)
        return round(0.5 + (ratio * 0.45), 2)


class LLMPlanner(InvestigationPlanner):
    """
    LLM-Powered Dynamic Investigation Planner.
    Uses real LLM gateway if configured and operational (ENGINE = LLM_PLANNER).
    NEVER fakes an LLM or returns canned responses.
    If LLM is unconfigured, unavailable, or encounters error/timeout/429,
    falls back safely to RuleBasedPlanner (ENGINE = RULE_ENGINE).
    Exposes operational statuses: LLM_CONFIGURED, LLM_UNAVAILABLE, LLM_ERROR, LLM_TIMEOUT, LLM_RATE_LIMITED.
    """

    def __init__(self, fallback_planner: Optional[InvestigationPlanner] = None):
        self.fallback_planner = fallback_planner or RuleBasedPlanner()
        self.llm_status: str = "LLM_UNAVAILABLE"

    def propose_next_action(
        self,
        state: InvestigationState,
        available_tools: List[ToolDefinition],
        permissions: List[str]
    ) -> PlannerDecision:
        from apps.agents.core.llm_gateway import LLMGateway
        gateway = LLMGateway.get_instance()

        if not gateway.is_configured():
            self.llm_status = "LLM_UNAVAILABLE"
            logger.info("[LLM PLANNER] LLM Gateway unconfigured. Falling back to RuleBasedPlanner (ENGINE = RULE_ENGINE).")
            decision = self.fallback_planner.propose_next_action(state, available_tools, permissions)
            decision.engine_type = "RULE_ENGINE"
            return decision

        self.llm_status = "LLM_CONFIGURED"
        try:
            # Construct real LLM prompt summarizing evidence and unresolved questions
            prompt = self._build_planner_prompt(state, available_tools, permissions)
            t0 = time.time()
            llm_response = gateway.generate_completion(
                prompt=prompt,
                system_prompt="You are an autonomous tier-3 SOC investigation planner. Analyze evidence and select the next optimal tool to resolve open security questions.",
                temperature=0.1
            )
            
            if not llm_response or not llm_response.get("content"):
                self.llm_status = "LLM_ERROR"
                logger.warning("[LLM PLANNER] Empty LLM response. Falling back to RuleBasedPlanner.")
                decision = self.fallback_planner.propose_next_action(state, available_tools, permissions)
                decision.engine_type = "RULE_ENGINE"
                return decision

            # Parse proposal from LLM text output
            proposal_text = llm_response.get("content", "")
            decision = self._parse_llm_proposal(proposal_text, available_tools, state)
            decision.engine_type = "LLM_PLANNER"
            return decision

        except Exception as e:
            err_str = str(e).upper()
            if "TIMEOUT" in err_str:
                self.llm_status = "LLM_TIMEOUT"
            elif "429" in err_str or "RATE" in err_str:
                self.llm_status = "LLM_RATE_LIMITED"
            else:
                self.llm_status = "LLM_ERROR"

            logger.error(f"[LLM PLANNER ERROR] {self.llm_status}: {e}. Safely falling back to RuleBasedPlanner.")
            decision = self.fallback_planner.propose_next_action(state, available_tools, permissions)
            decision.engine_type = "RULE_ENGINE"
            return decision

    def _build_planner_prompt(self, state: InvestigationState, tools: List[ToolDefinition], permissions: List[str]) -> str:
        q_summary = "\n".join([f"- {q_id}: {q.text} ({q.status})" for q_id, q in state.questions.items()])
        e_summary = "\n".join([f"- {e_id} ({e.evidence_type}): {e.value}" for e_id, e in state.evidence.items()])
        t_summary = "\n".join([f"- {t.name}: {t.description}" for t in tools])

        return f"""
INVESTIGATION CONTEXT:
Incident ID: {state.incident_id}
Remaining Budget Steps: {state.remaining_budget_steps}

EVIDENCE OBSERVED:
{e_summary or "None"}

UNRESOLVED QUESTIONS:
{q_summary or "None"}

AVAILABLE TOOLS:
{t_summary}

Task: Propose next tool execution or STOP decision.
Respond with format:
ACTION: RUN_TOOL or STOP
TOOL: <tool_name>
RATIONALE: <reasoning>
EXPECTED_GAIN: <float 0.0-1.0>
        """

    def _parse_llm_proposal(self, text: str, tools: List[ToolDefinition], state: InvestigationState) -> PlannerDecision:
        import re, json
        tool_names = {t.name for t in tools}
        action = "STOP"
        selected_tool = None
        rationale = text.strip() or "LLM proposed concluding investigation."
        expected_gain = 0.5

        # Check if LLM output is JSON
        if text.strip().startswith("{"):
            try:
                data = json.loads(text.strip())
                action = data.get("action", data.get("ACTION", "STOP"))
                selected_tool = data.get("tool", data.get("TOOL", None))
                rationale = data.get("rationale", data.get("RATIONALE", rationale))
                expected_gain = float(data.get("expected_gain", data.get("EXPECTED_GAIN", 0.5)))
            except Exception:
                pass

        for line in text.splitlines():
            line_clean = re.sub(r"[\*\#\`]", "", line.strip())
            if line_clean.upper().startswith("ACTION:"):
                val = line_clean.split(":", 1)[1].strip().upper()
                if "RUN" in val or "TOOL" in val:
                    action = "RUN_TOOL"
                elif "STOP" in val:
                    action = "STOP"
            elif line_clean.upper().startswith("TOOL:"):
                t_candidate = line_clean.split(":", 1)[1].strip()
                for tn in tool_names:
                    if tn.lower() == t_candidate.lower() or tn in t_candidate:
                        selected_tool = tn
                        break
            elif line_clean.upper().startswith("RATIONALE:"):
                rationale = line_clean.split(":", 1)[1].strip()
            elif line_clean.upper().startswith("EXPECTED_GAIN:"):
                try:
                    gain_match = re.findall(r"\d+\.\d+|\d+", line_clean.split(":", 1)[1])
                    if gain_match:
                        expected_gain = float(gain_match[0])
                except Exception:
                    pass

        # Fallback tool matching if action is RUN_TOOL but selected_tool is None
        if action == "RUN_TOOL" and not selected_tool:
            for tn in tool_names:
                if tn in text:
                    selected_tool = tn
                    break

        if action == "RUN_TOOL" and selected_tool:
            return PlannerDecision(
                action="RUN_TOOL",
                engine_type="LLM_PLANNER",
                tool_name=selected_tool,
                rationale=rationale,
                expected_information_gain=expected_gain
            )

        return PlannerDecision(
            action="STOP",
            engine_type="LLM_PLANNER",
            rationale=rationale,
            stop_reason="SUFFICIENT_EVIDENCE" if action == "STOP" else "NO_USEFUL_TOOLS"
        )



class HybridPlanner(InvestigationPlanner):
    """
    Hybrid Planner: Executes genuine consensus arbitration between RuleBasedPlanner
    and LLMPlanner. Both planners are evaluated; agreements are expedited, and disagreements
    undergo observable arbitration. Automatically falls back to RuleBasedPlanner when
    LLM inference is unconfigured, timed out, or rate-limited.
    """

    def __init__(self):
        self.rule_planner = RuleBasedPlanner()
        self.llm_planner = LLMPlanner(fallback_planner=self.rule_planner)

    def propose_next_action(
        self,
        state: InvestigationState,
        available_tools: List[ToolDefinition],
        permissions: List[str]
    ) -> PlannerDecision:
        from apps.agents.core.llm_gateway import LLMGateway
        gateway = LLMGateway.get_instance()

        rule_decision = self.rule_planner.propose_next_action(state, available_tools, permissions)

        if not gateway.is_configured():
            rule_decision.engine_type = "HYBRID"
            rule_decision.arbitration = {
                "mode": "FALLBACK_RULE",
                "rule_proposal": rule_decision.tool_name,
                "llm_proposal": None,
                "selected": rule_decision.tool_name,
                "reason": "LLM Gateway is not configured. Falling back to deterministic RuleBasedPlanner."
            }
            state.planner_engine = "HYBRID"
            return rule_decision

        llm_decision = self.llm_planner.propose_next_action(state, available_tools, permissions)

        if llm_decision.engine_type == "RULE_ENGINE":
            # LLM encountered error/timeout/429 and triggered fallback
            llm_decision.engine_type = "HYBRID"
            llm_decision.arbitration = {
                "mode": "FALLBACK_RULE",
                "rule_proposal": rule_decision.tool_name,
                "llm_proposal": None,
                "selected": rule_decision.tool_name,
                "reason": f"LLM inference unavailable or failed ({self.llm_planner.llm_status}). Fallback to RuleBasedPlanner."
            }
            state.planner_engine = "HYBRID"
            return llm_decision

        # Both planners provided genuine proposals: evaluate consensus!
        if rule_decision.action == llm_decision.action and rule_decision.tool_name == llm_decision.tool_name:
            decision = rule_decision
            decision.engine_type = "HYBRID"
            decision.rationale = f"Consensus reached: both Rule and LLM selected '{rule_decision.tool_name}'. Rule rationale: {rule_decision.rationale} | LLM rationale: {llm_decision.rationale}"
            decision.arbitration = {
                "mode": "CONSENSUS_AGREEMENT",
                "rule_proposal": rule_decision.tool_name,
                "llm_proposal": llm_decision.tool_name,
                "selected": rule_decision.tool_name,
                "reason": "Unanimous agreement between deterministic rules and LLM."
            }
            state.planner_engine = "HYBRID"
            return decision

        # Disagreement detected: execute observable arbitration
        valid_tool_names = {t.name for t in available_tools}
        if llm_decision.tool_name and llm_decision.tool_name not in valid_tool_names:
            chosen = rule_decision
            arb_reason = f"LLM proposal '{llm_decision.tool_name}' is not in available tool catalog. Arbitrated to rule proposal '{rule_decision.tool_name}'."
        elif llm_decision.expected_information_gain >= 0.85 and llm_decision.tool_name:
            chosen = llm_decision
            arb_reason = f"Arbitrated in favor of LLM proposal '{llm_decision.tool_name}' (expected gain: {llm_decision.expected_information_gain}) over Rule proposal '{rule_decision.tool_name}'."
        else:
            chosen = rule_decision
            arb_reason = f"Arbitrated in favor of Rule proposal '{rule_decision.tool_name}' over LLM proposal '{llm_decision.tool_name}' for forensic predictability."

        chosen.engine_type = "HYBRID"
        chosen.arbitration = {
            "mode": "ARBITRATION",
            "rule_proposal": rule_decision.tool_name,
            "llm_proposal": llm_decision.tool_name,
            "selected": chosen.tool_name,
            "reason": arb_reason
        }
        chosen.rationale = f"Hybrid arbitration: {arb_reason} | {chosen.rationale}"
        state.planner_engine = "HYBRID"
        return chosen
