# System Architecture & Technical Specifications

## 1. High-Level Architecture Overview

The platform uses a decoupled, event-driven architecture that rigorously separates deterministic cybersecurity rules from agentic LLM reasoning.

```text
┌─────────────────────────────────────────────────────────────┐
│                    External Telemetry Ingestion             │
│            (SMTP / EML / IMAP / Webmail Auth Logs)          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   Data Privacy Boundary                     │
│               (DataClassificationEngine)                    │
│      PUBLIC / INTERNAL ──▶ OpenRouter Gateway (Free)        │
│      CONFIDENTIAL / RESTRICTED ──▶ Local Ollama / Det       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│            Deterministic Email & HTML Parser                │
│    (MIME Structure / search-ms Monikers / UNC Callouts)     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
       Isolated Sandbox  Threat Intel  Exposure Engine
         (Playwright)     (NVD/KEV)    (OWA/Zimbra)
                │              │              │
                └──────────────┼──────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│               LangGraph Agent Orchestrator                  │
│       Typed State Machine over canonical SecurityState      │
│  Ingestion ──▶ Analysis ──▶ Vuln Research ──▶ Investigation │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│               Attack Graph Repository (Neo4j)               │
│ ThreatActor ──▶ Campaign ──▶ Email ──▶ CVE ──▶ Identity     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             Policy-Gated Response Engine                    │
│    Tenant Autonomy Levels (0-4) & Human Approval Gates      │
└─────────────────────────────────────────────────────────────┘
```

## 2. Multi-Dimensional Scoring Formulation

The platform rejects "black-box" single scores in favor of transparent, evidence-backed mathematical scoring:

$$\text{Overall Risk} = 0.15 \cdot \text{Exposure} + 0.20 \cdot \text{Exploitability} + 0.15 \cdot \text{Email Delivery} + 0.20 \cdot \text{Interaction} + 0.15 \cdot \text{Identity Impact} + 0.15 \cdot \text{Observed Attack}$$

- **Interaction Requirement Scoring**:
  - `NONE` (Zero-click): **100.0**
  - `VIEW` (Preview pane render): **90.0**
  - `HOVER`: **70.0**
  - `CLICK`: **50.0**
  - `OPEN_ATTACHMENT`: **40.0**
  - `EXECUTE_ATTACHMENT`: **30.0**
  - `MULTI_STEP`: **20.0**
