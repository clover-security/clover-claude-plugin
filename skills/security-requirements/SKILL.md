---
name: security-requirements
description: Surface security requirements before implementation. Dispatches to a sub-mode based on the argument. Currently supports `threat-questions` (STRIDE-style threat-modeling questionnaire). Trigger when the user runs `/security-requirements <mode>`, or proactively when designing a feature that touches authentication, authorization, user input, sensitive data (PII, secrets, tokens), network requests, file access, or third-party integrations. Also trigger on phrases like "threat model this", "security questions", "what could go wrong security-wise".
---

# Security Requirements

Pulls security thinking forward — *before* code is written — by dispatching to a focused sub-mode tailored to the situation.

## Dispatch

Read the argument that follows `/security-requirements`:

| Argument | Mode | Section |
| --- | --- | --- |
| `threat-questions` (default if omitted) | STRIDE-style threat-modeling questionnaire | [Mode: threat-questions](#mode-threat-questions) |

If the argument is unrecognized, list the supported modes and ask the user to pick one. Do **not** invent new modes.

When invoked proactively (no slash command — Claude is reading a plan), default to `threat-questions`.

---

## Mode: threat-questions

Surface security concerns by asking a small, targeted set of threat-modeling questions tailored to the feature.

### When to use

- The user is designing a feature that handles user input, authentication, authorization, secrets, PII, network calls, file I/O, or third-party APIs
- A plan is being drafted that introduces new entry points or trust boundaries
- The user explicitly asks for a threat model, security questions, or "what could go wrong"

Do **not** use for trivial changes (formatting, renames, internal refactors with no boundary changes).

### How to use

1. **Identify the trust boundary.** What is the entry point? Who/what crosses it (end users, other services, attacker-controlled input)?
2. **Pick 3–5 most relevant categories** from the STRIDE prompts below. Do not ask all of them — relevance beats coverage.
3. **Ask the questions in one turn**, numbered, so the user can answer in a single reply.
4. **Wait for answers** before proceeding to implementation.
5. **Summarize.** After the user answers, produce a short `## Threats considered` section listing the threats and the mitigation each one maps to. Fold the mitigations into the implementation plan.

### STRIDE prompts

#### S — Spoofing (identity)
- How is the caller's identity established at this entry point?
- Can the identity be forged, replayed, or bypassed (missing auth, weak token validation, trusted-header spoofing)?

#### T — Tampering (integrity)
- What inputs are accepted, and how are they validated and bounded?
- Can data be modified in transit or at rest by an attacker who reaches the storage/transport layer?

#### R — Repudiation (auditability)
- Which actions need an audit trail? Who is responsible for writing it, and is it tamper-evident?

#### I — Information disclosure (confidentiality)
- What sensitive data flows through this code (PII, secrets, tokens, internal IDs)?
- Where is it logged, cached, or persisted — and who can read those?
- Could error messages, stack traces, or response payloads leak internal structure?

#### D — Denial of service
- What input sizes, recursion depths, or request rates are accepted?
- Are expensive operations (DB scans, regex, external calls) exposed without rate limiting or timeouts?

#### E — Elevation of privilege
- What authorization checks gate this feature, and where do they live?
- Can a lower-privileged user reach higher-privileged behavior via IDOR, missing checks on a sub-path, or assumption of trusted caller?

### Output format

After the user answers, produce:

```
## Threats considered

- **<threat>** → <mitigation, mapped to a concrete code/config change>
- ...
```

Then update the implementation plan so each mitigation has a corresponding step. If a threat is acknowledged but explicitly out of scope, say so and note who owns it.

### Example

User: `/security-requirements threat-questions` — "I'm adding an endpoint that lets users export their data as a CSV."

Skill response:
> Before we sketch the implementation, a few threat questions:
>
> 1. **AuthZ** — does the endpoint scope the export to the requesting user's data only, and where does that check live?
> 2. **Info disclosure** — does the export include any fields the user shouldn't see (internal IDs, soft-deleted records, other tenants' data joined in)?
> 3. **DoS** — is there a row cap or rate limit? Could a user trigger a multi-GB export?
> 4. **Tampering** — is the CSV generation safe from formula injection (`=cmd|...`) when opened in Excel?
> 5. **Repudiation** — should we log who exported what, when, for compliance?
