# Platform Threat Model & Security Invariants

> **Canonical Security Model Notice:**  
> The comprehensive security model, adversarial defenses, and isolation invariants for FishingMails are documented in [**`docs/SECURITY_MODEL.md`**](file:///c:/Enterprise%20Agentic%20Email%20Exploitation%20Detection%20&%20Response%20Platform/docs/SECURITY_MODEL.md).  
> Please refer to [**`docs/SECURITY_MODEL.md`**](file:///c:/Enterprise%20Agentic%20Email%20Exploitation%20Detection%20&%20Response%20Platform/docs/SECURITY_MODEL.md) for the authoritative documentation covering:
> - Untrusted email input boundaries
> - Indirect prompt injection structural defenses and empirical verification results
> - `ToolRegistry` autonomy levels (0 to 4) and HMAC approval tokens
> - `NetworkGuard` SSRF prevention (RFC 1918, loopback, cloud metadata `169.254.169.254`)
> - Attachment decompression bomb prevention and MIME depth limits
> - Multi-tenant isolation invariants

---

## Quick Reference Summary

| Threat Category | Invariant & Defense | Status |
| :--- | :--- | :--- |
| **Untrusted Input** | Emails treated strictly as hostile data; structural JSON encapsulation | `VERIFIED` |
| **Prompt Injection** | System instructions separated from data; strict Pydantic JSON schemas | `VERIFIED` |
| **Sandbox SSRF** | `NetworkGuard` blocks RFC 1918, loopback, and `169.254.169.254` | `VERIFIED` |
| **MIME Bombs** | Max recursion depth $\le 10$, max size $\le 25\text{ MB}$, compression check | `VERIFIED` |
| **Unauthorized Actions**| `SafetyGate` enforces tenant autonomy (0-4); HMAC tokens for Level $\ge 3$ | `VERIFIED` |
| **Tenant Cross-Talk** | Foreign key tenant segregation on state and audit ledgers | `VERIFIED` |

For full technical details, consult [**`docs/SECURITY_MODEL.md`**](file:///c:/Enterprise%20Agentic%20Email%20Exploitation%20Detection%20&%20Response%20Platform/docs/SECURITY_MODEL.md).
