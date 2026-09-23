---
name: github-version-control
description: >-
  Standardized GitHub version control, branch lifecycle, commit formatting (Conventional Commits),
  and CI/CD automation workflow specifically tailored for the Enterprise Agentic Email Exploitation
  Detection & Response Platform. Use whenever creating commits, managing git branches, tagging releases,
  setting up remotes, or managing GitHub Actions in this workspace.
---

# GitHub Version Control & Repository Management Skill

This skill defines the standardized Git lifecycle, branch architecture, commit governance, and CI automation for the **Enterprise Agentic Email Exploitation Detection & Response Platform**.

---

## 1. Pre-Flight Security & Hygiene Rules

Before staging or committing any files:
1. **Mandatory GitHub Identity**: All commits must be made with:
   - `user.name`: `seniru-ekanayake`
   - `user.email`: `ekanayakeseniru0@gmail.com`
2. **Zero Secret Leakage**: Verify that no `.env`, private keys (`*.pem`, `*.key`), API tokens, or internal credentials are being tracked.
3. **Exclusion Check**: Ensure `.gitignore` is active and ignores:
   - `node_modules/`, `.next/`, `dist/`, `build/`
   - `__pycache__/`, `.pytest_cache/`, `.coverage`, `.venv/`
   - `apps/sandbox/temp_emails/`, `data/neo4j/`, `scratch/`, `*.log`, `*.db-journal`
4. **Clean Status Verification**: Always run `git status` before and after staging to verify exactly what changes are included.

---

## 2. Conventional Commit Standards

All commit messages in this repository must strictly adhere to the **Conventional Commits v1.0.0** format:

```text
<type>(<scope>): <concise description in imperative mood>

[optional body with rationale and technical details]

[optional footer(s), e.g., Refs: #123, BREAKING CHANGE]
```

### Allowed Types & Scopes

| Type | When to Use | Example Scopes |
| :--- | :--- | :--- |
| `feat` | New capability or agent module | `parser`, `sandbox`, `agents`, `threat-intel`, `attack-graph`, `response`, `ui`, `mcp`, `skills` |
| `fix` | Bug fix, parsing edge case, or scoring correction | `moniker`, `cve-analyzer`, `network-guard`, `auth-token` |
| `test` | Adding or refactoring unit, integration, or adversarial tests | `e2e`, `sandbox`, `gateway`, `orchestrator` |
| `docs` | Architecture docs, ADRs, Threat Models, README | `adr`, `threat-model`, `api-spec`, `walkthrough` |
| `refactor` | Code refactoring with no functional change | `types`, `schemas`, `llm-gateway`, `data-classification` |
| `chore` | CI/CD workflows, dependencies, `.gitignore`, repo configs | `ci`, `deps`, `gitignore`, `lint` |
| `security` | Hardening security boundaries, sandboxing, isolation | `sandbox`, `network-guard`, `token-scrubber` |

---

## 3. Branching Strategy

```text
main (Protected, Production Releases, Tagged vX.Y.Z)
  │
  └── develop (Active Integration & Staging)
        ├── feat/phase-12-mcp-subsystem
        ├── feat/phase-13-agentic-skills
        ├── fix/parser-search-ms-moniker
        └── security/sandbox-network-guard-isolation
```

### Branch Management Rules
1. **`main`**:
   - Production-stable code only.
   - Merges into `main` must represent completed, verified milestones and be tagged with a Semantic Version (`v0.1.0`, `v0.2.0`).
2. **`develop`**:
   - Central integration branch for ongoing work. Feature branches branch off from `develop` and merge back into `develop`.
3. **`feat/<feature-name>`**:
   - Dedicated branch for a specific phase or component.
   - Example: `git checkout -b feat/phase-12-mcp-subsystem develop`.
4. **`fix/<bug-name>` / `security/<cve-name>`**:
   - Short-lived patch branches for bug fixes and security hardening.

---

## 4. Standard Operational Procedures (Runbooks)

### Procedure A: Initializing Repository & Creating Baseline (`v0.1.0`)
```powershell
# 1. Initialize Git on main branch
git init -b main

# 2. Stage verified codebase
git add .

# 3. Commit baseline
git commit -m "feat(core): initial architecture baseline (Phases 1-11 end-to-end platform)"

# 4. Tag the baseline release
git tag -a v0.1.0 -m "Release v0.1.0: End-to-End Autonomous Email Exploitation Platform"

# 5. Create develop branch for active feature development
git checkout -b develop
```

### Procedure B: Developing a New Feature / Hardening Phase
```powershell
# 1. Ensure develop is up to date
git checkout develop

# 2. Create feature branch
git checkout -b feat/phase-12-mcp-subsystem

# 3. Work on changes, verify with tests
pytest tests/ -v

# 4. Stage and commit with conventional commit message
git add apps/agents/core/mcp_client.py packages/threat_intel/free_feeds.py tests/test_mcp_client.py
git commit -m "feat(mcp): implement stdio MCP client and free threat recon connectors"

# 5. Merge back to develop after tests pass
git checkout develop
git merge --no-ff feat/phase-12-mcp-subsystem -m "feat: merge phase 12 MCP subsystem into develop"
```

### Procedure C: Connecting & Synchronizing with GitHub Remote
```powershell
# Option 1: GitHub CLI (recommended if installed)
gh repo create Enterprise-Agentic-Email-Exploitation-Platform --private --source=. --remote=origin --push

# Option 2: Existing Remote URL
git remote add origin https://github.com/<org-or-username>/Enterprise-Agentic-Email-Exploitation-Platform.git
git push -u origin main --tags
git push -u origin develop
```

---

## 5. Verification Checklist Before Any Commit / PR

- [ ] `git status` shows only intended files (no unwanted artifacts or secret files).
- [ ] All unit and integration tests pass: `pytest tests/ -v`.
- [ ] Next.js dashboard builds without TypeScript errors (if modified): `cd apps/web && npm run type-check`.
- [ ] Commit message conforms to Conventional Commits format.
