# System Architecture & Technical Specifications

> **Canonical Specification Notice:**  
> The comprehensive, verified architectural specification for FishingMails has been consolidated in [**`docs/ARCHITECTURE.md`**](file:///c:/Enterprise%20Agentic%20Email%20Exploitation%20Detection%20&%20Response%20Platform/docs/ARCHITECTURE.md).  
> Please refer to [**`docs/ARCHITECTURE.md`**](file:///c:/Enterprise%20Agentic%20Email%20Exploitation%20Detection%20&%20Response%20Platform/docs/ARCHITECTURE.md) for the authoritative documentation covering:
> - Canonical `InvestigationState` specifications
> - Dual-planner architecture (`RuleBasedPlanner` vs `LLMPlanner`)
> - Hypothesis formulation and evidence feedback loops
> - `ToolRegistry` permission levels (0-4) and `SafetyGate` governance
> - End-to-end data flow diagrams and Mermaid workflows

---

## Quick Reference Summary

1. **Ingestion & Normalization**: RFC 822 / MIME emails are unpacked with strict bounds ($\le 10$ recursion depth, $\le 25\text{ MB}$ payload).
2. **State & Evidence**: Telemetry is converted into typed, immutable, SHA-256 hash-verified `Evidence` objects.
3. **Investigation Planning**:
   - `RuleBasedPlanner` (`PRODUCTION VERIFIED`): Deterministic, sub-millisecond execution ($\approx 0.01\text{ s}$).
   - `LLMPlanner` (`RUNTIME VERIFIED BUT NOT PRODUCTION READY`): Adaptive reasoning via OpenRouter API; mean latency $\approx 10.6\text{ s}$; automated fallback on rate-limits/errors.
   - `HybridPlanner` (`HYBRID RUNTIME VERIFIED`): Dual-path consensus.
4. **Execution Authority**: Language models propose actions; only `SafetyGate` and `ToolRegistry` have authorization to execute tools under tenant autonomy policy constraints (Levels 0–4).
5. **Persistence**: Forensic ledgers and attack graphs are stored in SQLite by default, with Neo4j support when configured.

For full technical details, consult [**`docs/ARCHITECTURE.md`**](file:///c:/Enterprise%20Agentic%20Email%20Exploitation%20Detection%20&%20Response%20Platform/docs/ARCHITECTURE.md).
