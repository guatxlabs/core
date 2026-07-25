# Security Policy

guatx-core is the **shared, security-critical core** of GuatX: a single audited implementation of
the SOQL query compiler and the field-masking / row-scoping layer that both Plume (blue SOC) and the
Forge console (red) depend on. A flaw here defeats a control in *both* products at once, so we want
to hear about it.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately via **GitHub Security Advisories** — the "Report a vulnerability" button on this
repository's **Security** tab. This keeps the report, the discussion and the fix coordinated and
private, and lets us credit you on disclosure. It is the only channel we monitor, so please use it
rather than a public issue, a pull request, or a direct message.

Please include: affected version/commit, a description, reproduction steps or a PoC, and the
impact. GitHub Security Advisories are private end-to-end, so no additional encryption is needed.

We aim to **acknowledge within 3 business days** and to agree on a remediation timeline with
you. We practise **coordinated disclosure** and will credit you (unless you prefer to remain
anonymous) once a fix is released.

## What is in scope

guatx-core's job is to compile untrusted query text into **read-only** SQL while enforcing masking
and scoping *by construction*. A security bug is anything that defeats that. In particular:

- **Masking / DENY choke-point bypass** — data exfiltration of a masked column: getting a value that
  `soql_field` should have wrapped in its mask (hash) or `Deny` expression to come through in the
  clear. `soql_field` is the single provenance choke-point; any path that reaches a column value
  without going through it (bypassing the compile-time `field_masks`) is in scope.
- **SOQL injection / compiler escape** — crafted query text that escapes value-quoting/inlining and
  injects SQL, or that makes the compiler emit anything other than the intended read-only query
  (mutation, sub-query to an unintended table, stacked statement).
- **RowFilter / authorizer bypass** — reading rows outside the caller's scope: defeating a
  `RowFilter` (`with_row_filter`) so the AND-joined predicate is dropped, weakened, or side-stepped,
  or otherwise cross-scope / cross-tenant row access through the compiled query.
- **Secret leakage** — a `SecretValue` / secret material escaping redaction (into a `Debug` output,
  an error, or a compiled query/log) rather than being zeroized and `REDACTED`.

## What is NOT a vulnerability

- **Misusing the library in your own application.** guatx-core enforces masking, read-only
  compilation, and row-scoping *for the queries it compiles*; it cannot secure code paths that
  bypass it entirely. If your app reads the database directly, hands the compiler a schema/mask set
  that grants access, or feeds secrets to something outside `SecretValue`, that is an integration
  bug in your app, not a flaw in the core.
- **A feature request for a stricter default.** Report a *defeat* of an existing control, not the
  absence of a control we do not claim.

## Supported versions

guatx-core is pre-1.0. Security fixes land on `main` and in the latest tagged release. Older tags
are not maintained; please upgrade.

| Version | Supported |
|---------|-----------|
| `main` / latest release | ✅ |
| older tags | ❌ |

## Hardening & audits

The core safety controls — the single SOQL compiler, the `soql_field` masking choke-point, `Deny`
/ hash masks applied at compile time, `RowFilter` row-scoping, and secret redaction/zeroization —
are covered by tests (including a differential parity bench against the origin Plume compiler) and a
CI pipeline that runs `cargo audit` and secret scanning on every push.
