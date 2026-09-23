# Enterprise Agentic Email Exploitation Detection & Response Platform

An enterprise-grade, model-agnostic cybersecurity platform designed to detect, investigate, correlate, and respond to **email-delivered and email-rendering exploitation**, including modern zero-click and low-interaction preview pane attacks (where a victim only needs to render or view an email).

---

## 🚀 Key Architectural Capabilities

1. **Email Rendering & Moniker Exploitation Detection**:
   - Detects low-interaction URI moniker attacks (e.g. `CVE-2023-35636` search-ms preview exploits, `CVE-2024-21413` MonikerLink, `CVE-2023-23397` zero-click MAPI appointments).
   - Deep HTML parsing for active scripts, forms, hidden iframe elements, and forced UNC/SMB NTLM hash theft callouts.
2. **First-Class Email Attack Surface Engine**:
   - Continuous discovery of internet-facing mail hosts (Exchange/OWA, Zimbra, Google Workspace, Roundcube).
   - Delineates 10 non-collapsed asset states: `ASSET_DISCOVERED` → `ASSET_EXPOSED` → `SOFTWARE_IDENTIFIED` → `VERSION_IDENTIFIED` → `VULNERABLE` → `KNOWN_EXPLOITABLE` → `EMAIL_DELIVERABLE_EXPLOIT_POSSIBLE` → `ATTACK_OBSERVED` → `COMPROMISE_SUSPECTED` → `COMPROMISE_CONFIRMED`.
3. **Data Privacy Boundary (`DataClassificationEngine`)**:
   - Classifies payloads into `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, and `RESTRICTED`.
   - Strictly enforces that `CONFIDENTIAL`/`RESTRICTED` emails never leave the perimeter to third-party LLMs (routed locally to Ollama/deterministic analysis with immutable audit trails).
4. **Abstract LLM Gateway & Dynamic Capability Validation**:
   - Model-agnostic layer defaulting to `openrouter/free` with support for local Ollama.
   - Dynamically validates tool calling, JSON reliability, and context size at startup to survive OpenRouter free model rotations.
5. **Typed LangGraph Security Workflow**:
   - 6 typed agent nodes over a shared `SecurityState`: Ingestion → Email Analysis → Vulnerability Research → Exposure Correlation → Investigation → Response Planning.
6. **Isolated Behavioral Sandbox**:
   - Playwright-instrumented safe execution environment.
   - Strict `NetworkGuard` blocking RFC1918 private subnets, localhost, and cloud metadata endpoints (`169.254.169.254`).
7. **Attack Graph Topology (Neo4j / In-Memory)**:
   - Traverses directed attack chains from Threat Actor → Campaign → Email → CVE → Asset → Identity → Session.
8. **Policy-Gated Human-in-the-Loop Response Engine (`ToolRegistry`)**:
   - Autonomous multi-tier tenant levels (Levels 0–4) with rate limiting and emergency killswitches.
   - High/Critical actions (`revoke_session`, `disable_account`) generate approval tokens (`APP-XXXXXX`) requiring explicit human authorization.

---

## 📂 Repository Monorepo Structure

```text
├── apps/
│   ├── api/             # Fastify REST API Gateway with OpenAPI/Swagger docs
│   ├── web/             # Next.js 14 SOC Dashboard & Attack Graph Visualizer
│   ├── agents/          # LangGraph Security Orchestrator & Investigation Service
│   └── sandbox/         # Playwright Isolated Behavioral Sandbox
├── packages/
│   ├── schemas/         # Canonical JSON schemas, Pydantic models & TypeScript types
│   ├── threat_intel/    # Deterministic CISA KEV, NVD, and MITRE ATT&CK Ingestors
│   ├── email_parser/    # Deterministic RFC822 MIME and Active HTML Analyzer
│   ├── attack_surface/  # Email Attack Surface Engine & Multi-Dimensional Scoring
│   └── attack_graph/    # Abstract AttackGraphRepository (Neo4j & In-Memory)
├── tests/
│   ├── e2e/             # Master Demo Scenario End-to-End Tests
│   └── adversarial/     # Prompt Injection, SSRF, and MIME Bomb Test Suite
└── docker-compose.yml   # Full local infrastructure cluster
```

---

## ⚡ Quickstart: Local Docker Deployment

Start the entire open-source infrastructure cluster:

```bash
docker-compose up -d
```

Infrastructure services exposed:
- **PostgreSQL (`pgvector`)**: `localhost:5432`
- **Neo4j Community**: `localhost:7474` (HTTP) / `localhost:7687` (Bolt)
- **NATS Event Bus**: `localhost:4222` / `localhost:8222` (Monitor)
- **Valkey (Redis)**: `localhost:6379`
- **MinIO Object Storage**: `localhost:9000` / `localhost:9001` (Console)

---

## 🧪 Running Automated Tests

Run the complete 27-test monorepo test suite:

```bash
python -m unittest discover -s . -p "test_*.py"
```

---

## 🛡️ Master Demo Scenario Execution

Run the end-to-end synthetic demonstration:

```bash
python tests/e2e/test_demo_scenario.py
```
