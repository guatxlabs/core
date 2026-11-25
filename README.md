# guatx-core

[English](README.md) | [Français](README.fr.md)

**GuatX shared core — neutral, public.** The ~70 % common to Plume (blue SOC, published under AGPL-3.0:
[guatxlabs/plume](https://github.com/guatxlabs/plume)) and to the Forge console (red),
extracted so that the critical primitives have **a single implementation**.

*Rust · lib · minimal dependencies: `regex`, `serde_json`, `secrecy`, `zeroize` (4 crates, all already
present in the consumers' dependency tree — no new native/compiled crate).*

Licensed under LGPL-3.0-or-later, see [COPYING.LESSER](COPYING.LESSER).

## Why
- **Single source of truth**: a bug fixed / a feature added once benefits both products.
- **Security consistency**: the guards (read-only compilation, anti-injection allowlist, auth) are
  **critical** → one audited implementation is better than two that diverge.

## Contents
- `soql` — the **GXQL** compiler (*GuatX Query Language*; **formerly called "SOQL"** — same
  language, same syntax, only the name changes: `SOQL` was the name of Salesforce's query language).
  The **Rust module stays `soql`**: the rename applies to the **language name**, not to the API — the
  public identifiers (`guatx_core::soql::*`, `soql_esc`, `GUATX_SOQL_MAX_*`) are **unchanged**, the
  lib was tagged v0.2.2 at the rename and is consumed as is by Plume and Forge.
  **Where the rename stops, so that it is not taken for an oversight:** what a USER reads says
  `GXQL` (interfaces, documentation, rendered error messages); what a CONTRIBUTOR reads keeps `soql`
  (module name, identifiers, and the comments of `src/soql/` that describe them).
  Renaming the prose of a module called `soql`, next to `soql_*` functions, would have made the
  code LESS readable, not more. The criterion is therefore the API, not the file.
  Plume's **complete SPL-like compiler**, promoted here and made **schema-generic**
  (`Schema::events()` for Plume · `Schema::forge()` for Forge). A base (`search` / `metric` /
  `<alt>`) then **18 pipeline stages**, under **20 names** (`head`/`limit` and `top`/`rare` are two
  alias pairs): `stats` · `timechart` · `where` · `sort` · `head`/`limit` · `rex` · `fields` ·
  `table` · `rename` · `dedup` · `top`/`rare` · `eventstats` · `rate` · `eval` · `mvexpand` ·
  `lookup` · `append`[..] · `join` f[..]. These two figures are the **dispatcher's**, and a test
  compares them to it (`the_readme_step_count_is_the_one_the_dispatcher_gives`) — the list above
  can therefore no longer stop following the code, which is exactly what had happened to the "16" it
  used to announce. **Read-only** SQL, values **escaped+inlined**
  (`soql_esc`, doubled quotes), idents validated, SQL keywords forbidden in `eval`, recursion ≤3.
  The `regexp`/`re_cap` UDFs (for `=~`/`rex`) are registered by the consumer on its connection.

Coming next: auth (argon2 + anti-rebinding host-guard), read-only execution, packaging helpers.

## Golden rule
**Nothing offensive here.** Attack modules, WAF/CF evasion, ROE logic → stay in **Forge**, a separate
repository that depends on this core. `guatx-core` contains only generic infrastructure (query, auth,
storage).

## Usage
```rust
use guatx_core::soql::{compile, Schema};
let c = compile("search severity=HIGH | stats count by mitre | sort -count", &Schema::events())?;
// c.sql = read-only SQL ready to execute; c.columns = output columns.
// NB: the compiler ESCAPES and INLINES the values (no bound parameters) — escaping is
// delegated to the target's `Dialect` (SQLite/DuckDB/ClickHouse), it is the single choke point.
```
```sh
cargo test                   # 194 tests (166 unit + 22 integration + 5 differential parity + 1 doctest), 2 ignored
cargo test --features forge  # 216 tests (Forge schema + tests enabled)
cargo test --all-features    # 225 tests (+ `ai` and `cold_tier` modules)
```

### Field name and full-text search
A field name accepts only **letters, digits and `_`**.

**What is refused.** In a base filter (`search …`) or a `where`, a term whose **left-hand side** has
the *shape* of a field name without being a valid one is **refused**, with a message that names that
left-hand side. Both filter syntaxes are concerned:

| Syntax | What decides the name | Refused |
|---|---|---|
| token `nom<op>valeur` (`=` `:` `!=` `>=` `<=` `>` `<` `=~`), attached or spaced | the left-hand side of the operator, delimiting blanks removed | `x-forwarded-for=1.2.3.4` · `http.status>=500` · `foo-bar = 1` · `x-forwarded-for="10.0.0.1"` (quoting the *value* does not exempt) |
| clause `nom [not] in (…)` | everything before `in` up to the token boundary (the **blank**, the only one in this language), **minus** the leading opening parentheses, which are grouping — **not** a character class | `src-ip in (10,11)` · `cache/status in (200,302)` · `user@host in (1,2)` · `-foo in (1,2)` · `foo(host in (1,2)` · `count(src_ip in (10,11))` |

Letting it through would give an unbounded full-text scan — or, for `in (…)`, a filter on a *different*
field than the one written (the suffix after the separator): in both cases a set of rows different
from the one requested, without a word. The guard applies under the same conditions in a sub-search
(`append […]`, `join f […]`), at any depth.

**What is NOT refused.** A **leading** opening parenthesis is **grouping**, not part of the name: it
is removed from the head of the token, put back into the filter text, and the rest must be a whole
identifier. Measured: `search (dport in (80,443))` and `search ((foo in (1,2)))` give the SQL of
v0.2.0 byte for byte, while `search foo(host in (1,2)` is refused. The peeling only happens **at the
head**: `search (a) in (1,2)` claims `a)` and is refused.

A **quoted phrase** remains a full-text search, unchanged:
`search "user-agent=curl/7.68"`, `search "x-forwarded-for in (1,2)"`, `search "foo-bar"=1`. Quoting
counts for what it covers **to the left of the operator**, not for there being a quote somewhere:
`search source="web"` remains the indexed filter `"source" = 'web'`, and
`search x-forwarded-for="10.0.0.1"` is refused. An **unclosed** quote exempts nothing.

**The escape hatch.** In a **base filter**, the error message suggests your own text in quotes — it
is a slice of the text you typed, spaces and punctuation included. Measured: `search foo-bar = 1`
suggests `"foo-bar = 1"`, and `search "foo-bar = 1"` compiles to `message LIKE '%foo-bar = 1%'`.
Quotes being **delimiters** (the tokenizer never keeps them), the suggested text is yours *without
its inner quotes*: `search foo-bar=a"b"` suggests `"foo-bar=ab"`. The `where` stage also refuses an
invalid name, but with its own wording and **without** a suggestion (`where : champ invalide : foo-bar`
— measured): `where` has no full-text search to fall back on.

**Measured limit, not closed:** this guard does not exist in `eval`, and cannot exist there — in an
expression, `-` is the subtraction operator. `search | eval x = foo-bar` emits `(foo-bar)` and
`eval x = foo - bar` emits `(foo - bar)`: **these two SQL strings are not byte-identical** — they only
differ by blanks (measured by the test below), and SQLite compiles them into the **same program**
(measured: `EXPLAIN SELECT (foo-bar) FROM t` and `EXPLAIN SELECT (foo - bar) FROM t` give identical
bytecode, sqlite 3.53.3). Nothing in the input therefore separates the two readings; a misspelt name
fails there at **execution** (nonexistent column) and not at compilation; even there, an isolated `'`
is rejected (`eval : chaîne non terminée`), not inlined raw.

**No written name comes out raw in the SQL — a derived property, not an enumerated one.** A field
name that reaches the SQL must either be **refused** (a valid identifier contains no single quote),
or come out **escaped** (a legitimate value has its `'` doubled). The test
`no_user_written_name_reaches_the_sql_raw_whatever_the_step` generates from the dispatcher — without
naming any stage — a token carrying a `'` in every argument position of every stage, on the 4
schemas, and checks that its **raw form** never appears in the emitted SQL: otherwise a name would
have leaked without validation (`json_extract(fields,'$.a'b')`, broken literal) or a value would
have come out unescaped. This is what replaces the former hand-written enumeration (which claimed to
list "the other stages" and forgot `rex` and `join`, both measured as validating) — `eval` remains
the only exception documented above, and it still refuses the unterminated `'`.

**A comma-separated field list is decided in a single place** (`FieldList`): `stats
by`, `timechart by`, `eventstats by`, `metric by`, `fields`, `dedup`, `table` and `lookup … OUTPUT`.
No entry is dropped there, so a requested list cannot evaporate silently nor emit invalid SQL.
Measured, refused everywhere the separator is the **comma alone**: `by`, `by ,`,
`by ,src_ip`, `by src_ip,`, `by src_ip,,host`, `fields`, `fields ,`, `fields ,src_ip`, `dedup ,src_ip`.

**A name in `by` must be in scope** (`field_in_scope`, the same door for `stats by`, `timechart by`,
`eventstats by`). The criterion is derived from field resolution: a live column (a real column of
the base, a label declared by `metric … by <label>`, an alias produced by an upstream stage), a
knowledge object alias whose source is live, or a key of the JSON bag as long as the bag (`fields`)
is still in scope — keys are dynamic, an absent key groups under NULL. Any other name is refused,
naming it and listing the scope. What this refusal closes, measured: `metric x | stats max(value) by date`
compiled to `GROUP BY "date"`; for lack of a column, SQLite reads `"date"` as the literal string, all
rows fall under a single label and the query returns ONE row whose first column is
"date" — a total disguised as a group. Same mechanism after the bag is folded away:
`… | stats count by src_ip | stats sum(count) by dport`. The message points to `timechart span=<durée>` when the name is a
calendar word (`date`, `hour`, …): the time slice exists in the language, it is `timechart span=`,
not `by hour`. Known limit: on a base with a JSON bag, `by date` remains a plausible JSON key
(`fields.date`) — undecidable at compile time, the output then shows a NULL key, never the label.

**Under a field mask, the JSON bag is never read raw** (`bag_may_carry_masked_value`, a single
decision for the whole compiler). The bag (`fields`) is written as the producer of the event
supplies it: it can carry a key of any name, including that of a real column. As soon as the
caller's mask set is not empty, every read of the bag therefore removes each masked name — in
output, in an expression, as a group, partition or sort key, and for an alias that only differs
from it by case — and what cannot read a redacted bag is refused, saying so: a base predicate
on the bag (`search fields=…`, wildcard, regular expression, `in`) and a join whose key is the bag.
Accepted cost: a masked caller filters by key name (`search <clé>=…`), no longer on the text of the
bag; this applies to every caller when a deny rule applies to all roles. Without any mask, the SQL
emitted is unchanged byte for byte.

**What the compiler does not read is refused, never dropped nor misread.** Three families of forms
returned a wrong result without an error; they are refused, saying what to write, and no grammar is
added. *Splitting into stages respects double quotes*: a vertical bar or a bracket
in a quoted value (`search url=~"/a|/b" | stats count`) is no longer a boundary; an
unclosed quote is refused. In a `rex` stage, and only there, `\"` is a quote of the pattern.
*`search` joins its terms with AND*: a bare `OR`, `AND` or `NOT` and a grouping parenthesis
are refused (alternative: `champ in (a, b)` or `champ=~"a|b"`; negation: `champ!=valeur` or
`champ not in (…)`; the word or the parenthesis as text: in quotes). *A stage reads a fixed
grammar*: a second aggregate or an alias in `stats`, `eventstats` and `timechart` (`stats count as n` →
`| rename count AS n`), an uppercase `BY`, an extra argument to `sort`, `head`, `top`, `rare`,
`mvexpand`, `lookup`, `rate`, `append` or `join` are refused, naming the token. Accepted cost: an
isolated double quote can no longer be written outside a quoted `rex` pattern (in a regular
expression: `\x22`). Without any of these forms, the SQL emitted is unchanged byte for byte.

**This is not a list of stages, it is a property checked on the ones the code declares.** A
hand-written enumeration had already missed a stage: `lookup … OUTPUT` split the string
itself, so that `lookup t k OUTPUT` and `lookup t k OUTPUT ,` compiled by falling back on the
"OUTPUT absent" branch — the requested projection vanished without a word. Two tests replace
the enumeration, and they name no stage:
- `no_typed_field_list_can_evaporate_whatever_the_step` **reads the dispatcher** and the compiler of
  each stage, derives from them the list positions (*a position is a list of names if changing the
  names changes the SQL*) and checks on each one, on the 4 shipped schemas, that a list without any
  name is refused. Two modes, of different reach, and this is written: when the list is **the whole
  argument** (`fields X`, `table X`), detection is purely behavioural, independent of how the stage
  splits; when a **keyword** introduces it (`by`, `OUTPUT`), that keyword is read
  in the stage's compiler — the keywords of the shipped stages are read there; a *future* stage that
  would introduce a list with a keyword this test does not detect would escape it. This limit remains
  a matter of *lost projection*, never of security: the invariant "no invalid name reaches
  the SQL" is held separately and **universally**, for every present or future stage, by
  `no_user_written_name_reaches_the_sql_raw` (it plants a name carrying a quote in every
  argument position of every stage and checks that it never reaches the emitted SQL);
- `every_comma_split_of_the_compiler_is_the_door_or_a_written_exception` **reads the source**: every
  split on the comma is either the door, or an exception declared with its reason (values of
  `in`, pairs of `rename`, macro arguments). The detector keys on the **comma separator** (a
  line carrying `split` — the whole family, `split`/`splitn`/`split_once`/`split_terminator`/
  `split_inclusive`/`rsplit` — **and** a comma literal `','` or `","`), so a new hand-written split
  makes it fail whatever the method. **Out of reach, and this is written in the test:**
  a comma hidden behind a named constant or a numeric cast, or a split spread over
  several lines — obfuscations one does not write by accident. The **guarantee** for the dispatcher's
  stages remains the EFFECT guard above, which observes the result whatever the writing;
  this one is a guard on form.

`table` and `lookup … OUTPUT` have a different grammar — the **blank** is also a separator there
(`table a b` and `OUTPUT a b` are legitimate, measured) — so a *run* of separators there is
indistinguishable from a single one and is reduced: `table a,,b` gives `a` and `b` (accepted limit,
measured). What stays closed: `table ,` and `lookup t k OUTPUT ,` are refused instead of vanishing.
`table *` and bare `table` remain **deliberate pass-throughs** (they do not restrict the projection),
unchanged, like `lookup` **without** `OUTPUT` (nothing was requested) — the difference lies in what
the user wrote: the **typed** `OUTPUT` keyword is an explicit request, the absence of a keyword is not one.

**The list of *values* of a `champ in (…)` is the neighbouring door, and its boundary is here.** It
is not a list of names, and the two cannot decide alike because their **domains** differ:
the empty string is not a field name (refusal), but it is a legitimate **value** (an event can
carry `host=''`). What is tested is therefore the **written text**, before quotes are removed:
`in ("",b)` gives `IN ('','b')` — the **requested** empty string survives (it used to vanish, measured:
`IN ('b')`); an entry without any text is a **run of separators**, indistinguishable from a single one
as in `table`, so `in (a,,b)` gives `IN ('a','b')` (accepted limit, measured); and the
**entirely** empty list (`in ()`, `in (,,)`) gives no value — SQLite having no `IN ()`, it
falls back on `1=0` (`in`) / `1=1` (`not in`), never on a filter that vanished.

### Compilation bounds (the query text is UNTRUSTED input)
Compilation happens **before** any execution budget of the store: it therefore carries its own bounds.
Each has a safe default and is set through the environment. **When it is exceeded, a clear error is
returned to the caller** — never a panic, never a value silently substituted.

| Variable | Default | Ceiling | What it bounds |
|---|---|---|---|
| `GUATX_SOQL_MAX_SPAN_SECS` | `315360000` (10 years) | `315360000` | the `timechart span=` bucket (seconds) |
| `GUATX_SOQL_MAX_STAGES` | `64` | `1024` | the number of pipe stages of a pipeline |
| `GUATX_SOQL_MAX_SQL_BYTES` | `1048576` (1 MiB) | `16777216` | the size of the emitted SQL, checked after each stage |
| `GUATX_SOQL_MAX_TEXT_BYTES` | `1048576` (1 MiB) | `16777216` | the size of the accepted query text |

A security bound can be **lowered, not removed**: above the ceiling the value is refused
(the span bound, whose ceiling equals the default, can therefore only be lowered).

Exact reach of the SQL bound: it is checked **after** each emitting stage (the base, each
computed field, each automatic lookup, then each pipe stage). The **transient** peak of a
stage is therefore not bounded by it: it is the bound on the **input text** that contains it. Order of
magnitude measured for the pair: 400 006 bytes of text produce 4 600 089 bytes of SQL (×11.5) — hence
refusal, the SQL bound being crossed from the first stage.

A variable that is **present but unreadable** (non-numeric, ≤ 0, above the ceiling) is reported as
a configuration error, and not silently brought back to the default: a bound the operator believes
they set must never be ignored without saying so. Accepted consequence, to know before deploying:
as long as the variable is unreadable, **every query that consults this bound fails** (fail-closed),
and the message says so — it is a *server* configuration error, not an error in the query. Only a
**valid** value is cached (read once per process): fixing an unreadable variable does **not**
require restarting the service; on the other hand a valid value already read stays frozen until
restart.

## Status
- ✅ Plume's compiler **promoted + generalised** here (18 pipeline stages, schema-generic). Full suite: 194 tests (216 with `--features forge`, 225 with `--all-features`), measured on 2026-11-24 on version 0.2.6.
- ✅ Consumed by the Forge console and by Plume via a **git-dep pinned by tag**:
  `guatx-core = { git = "https://github.com/guatxlabs/core", tag = "v0.2.6" }` — a standalone clone of
  either product compiles without having this repository next to it. **Pin `v0.2.6` or later.**
  Three reasons, of very different severity:
  - `v0.2.0` emitted, on untrusted input, filters on a column the user
    had never named (silent false negative in a detection rule) — fixed in `v0.2.1`,
    see the notes of that tag. This is the **correctness** reason: do not pin `v0.2.0`.
  - `v0.2.1` PREDATES the renaming of the language to GXQL. Its code is identical to that of
    `v0.2.2` except for three error messages, but its README still talks about "SOQL": a reader
    who follows the pin lands there and reads the old name. This is the **documentation** reason — not a
    defect, just a tag that no longer tells the story of the product.
  - Tags before `v0.2.6` silently dropped or misread some query forms (a token no stage reads, a bare
    `OR`, an unknown `stats … by` key), and before `v0.2.5` a predicate could read the JSON bag raw
    under a field mask. `v0.2.6` refuses what it does not read; see the notes of tags `v0.2.4` to
    `v0.2.6`. This is the second **correctness** reason, and why Plume and Forge both pin `v0.2.6`.
- ✅ **Adoption by Plume completed**: differential parity harness on the corpus of the queries
  shipped with the product (bench `tests/plume_parity.rs`, 0 unexpected divergence), switch-over of the daemon, then removal
  of the internal compiler. No functionality lost — this core is now the only implementation.
