# Contributing to guatx-core

Thanks for your interest in guatx-core — the shared, security-critical core of GuatX (the SOQL
compiler + masking/scoping layer that both Plume and the Forge console depend on). Contributions are
welcome, under a few rules that exist because this crate is **safety-critical**: a bug here breaks a
control in *both* products at once.

By contributing you agree that your contribution is licensed under **LGPL-3.0-or-later** (the
project license), and you certify the [Developer Certificate of Origin](https://developercertificate.org/)
by signing off your commits (`git commit -s` → adds `Signed-off-by:`).

## Non-negotiable: the core invariants

A pull request that weakens any of these will be **rejected**, no matter how useful the feature:

- **One SOQL compiler — never fork it.** The compiler is the single masking/scoping choke-point that
  serves both Plume (`Schema::events()`) and Forge (`Schema::forge()`). Fix and extend it *in place*.
  Do not copy it, special-case a caller, or add a second code path that emits SQL — a fork is a
  control that drifts out of sync and eventually diverges from the audited one.
- **Masking / DENY is applied by construction, never re-implemented per caller.** `soql_field` is the
  UNIQUE function that turns a column name into emitted SQL, and it is where the compile-time
  `field_masks` (`Deny` / hash) are applied. No caller may resolve or emit a column value on its own;
  everything goes through `soql_field` so masking cannot be forgotten.
- **The compiler stays read-only, with values escaped + inlined.** No path may emit a mutation, a
  stacked statement, or an unescaped value. Query text is untrusted input.
- **Row-scoping holds.** A `RowFilter` posted via `with_row_filter` must remain AND-joined into the
  compiled query; do not add a path that drops, weakens, or side-steps it.
- **Secrets are redacted and zeroized.** A `SecretValue` must never reach a `Debug` output, an error,
  a compiled query, or a log in the clear.
- **Golden strings are reviewed, never silently refreshed.** Some SQL fragments are pinned by
  literal golden strings instead of the differential bench. Updating a golden alongside the code it
  pins requires an explicit maintainer review: say in the PR why the emitted SQL had to change.
- **A change to the generic compiler is a change to every dependent.** If you touch the shared
  machinery — `RowFilter`, `Schema::events()`, the masking path, anything not behind the `forge`
  feature — it affects **both** Plume and Forge. Say so in the PR and ping the maintainers; the
  differential parity tests must still pass.

When in doubt, add a test that proves the invariant still holds.

## Building & testing

guatx-core is a **standalone Rust library** (`Cargo.toml` at the repo root, minimal dependencies).
No Python, no database, no sibling checkout — a plain clone builds and tests.

```sh
cargo test                        # default build: feature OFF (~70% shared, the community build)
cargo test --features forge       # + the Forge schema (Schema::forge()) and its tests
cargo test --all-features         # + the `ai` and `cold_tier` modules (CI gates this pass too)
cargo clippy --all-targets --all-features   # advisory lint — do not INCREASE the warning count
```

Everything must be **green** and **offline** — tests must not touch the network. The default
(feature-OFF) build is the community build and must stay byte-compatible: `--features forge` only
*adds* the red schema and its tests, it never changes the shared compiler.

## Code style

- **`openssl`-free, minimal deps.** The core pulls only `regex`, `serde_json`, `secrecy`, `zeroize`
  (all already present in both consumers' trees — no new native/compiled crate). Do not add a
  dependency without discussing it first.
- **Product-specific code lives behind a feature.** Anything specific to Forge goes behind the
  `forge` feature (default OFF); the shared compiler stays product-agnostic.
- **Secrets via the SPI.** Secret material flows through `secret::SecretValue` / the provider SPI —
  never a bare `String` that could be logged.

## Pull requests

1. Open an issue first for anything non-trivial, so we can agree on the approach.
2. One logical change per PR. Keep the diff focused.
3. Include tests. Preserve or improve coverage.
4. Run `cargo test`, `cargo test --features forge`, `cargo test --all-features`, and
   `cargo clippy --all-targets --all-features`. The three test passes must be green (clippy is
   advisory: the tree currently emits a known baseline of warnings — do not increase that count).
5. Sign off your commits (`-s`).
6. **Security issues do not go here** — see [`SECURITY.md`](SECURITY.md).

## A word on intent

guatx-core exists so the critical primitives — read-only compilation, masking, row-scoping — have
**one** audited implementation shared by both products. Contributions that would give a caller a way
around those controls, or that split them into a second divergent path, are out of scope for this
project.
