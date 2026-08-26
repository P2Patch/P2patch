# Technique-completeness audit — a second axis for the POV sets

## Why this exists (and how it differs from path completeness)

`fix_povs/COMPLETENESS_CHECKLIST.md` audits **path completeness**: does
the set exercise every source-to-sink *path* the official fix guards? This
document audits the orthogonal axis — **technique completeness**: for a single
path, does the set exercise every distinct *payload technique* that reaches the
sink, when a plausible partial patch could block one technique and leave another
open?

The two axes come apart exactly when the official fix is a **broad control that
neutralizes many techniques at once** (a context restriction, an unconditional
quoter, a wholesale feature removal), while a *pipeline* patch might instead
block one specific technique (a type-name filter, a metacharacter blacklist).
A path-complete set using one representative payload then scores that weaker
patch a **false 1.0**. The pipeline's own hardening exploiter surfaced these:
the spring-boot-admin `RestrictedTypeLocator` patch blocked `T(...)` type
references but not `Class.forName` reflection — our 12 type-reference POVs
missed it.

## The oracle still governs (nothing changes about certification)

A technique POV is only a **fixPOV** POV if it reproduces on the unpatched
code AND is **blocked by the official fix**. A technique the official fix does
*not* block is either a **residual** POV (if it's a genuine gap — see
`residual_povs/`) or **not promotable** (if it's by-design / not attacker-
reachable, like "the ScriptStringLookup class still exists"). Test every
candidate; never add one that doesn't certify.

**Discrimination test (the bar for adding a technique POV):** describe a
plausible partial patch that blocks every technique already in the set but not
this one. If you can't, the technique is redundant — skip it.

---

## Technique taxonomy by vulnerability class

Only techniques the *official fix* blocks can become gt POVs — that's why the
taxonomy is organized by what kind of control the fix is.

### CWE-094 — expression / code injection (SpEL, script lookups, reflection)

When the fix is a **SpEL context restriction** (`StandardEvaluationContext` →
`SimpleEvaluationContext.forPropertyAccessors`), it disables *all* of the
following at once, so each is a valid discriminating technique:

- **T1 type reference** — `T(java.lang.Runtime).getRuntime().exec(...)`
- **T2 reflection / method-chaining** — `''.getClass().forName('...').getMethod(...).invoke(...)` (no `T(...)`)
- **T3 constructor invocation** — `new java.lang.ProcessBuilder('...').start()`
- **T4 static field / bean navigation to a live object** — only if it reaches an
  invokable sink; note `SimpleEvaluationContext.forPropertyAccessors` *permits*
  plain property reads, so a pure property-read payload is NOT blocked by the fix
  → not a gt technique (residual or not-promotable).

When the fix is a **wholesale feature removal** (commons-text: drop script/dns/url
from the default interpolator) or a **reflection allow-list** (ff4j: whitelist at
`Class.forName` sinks), technique diversity does NOT discriminate — once the
feature is gone / the class rejected, every payload technique fails identically.
One representative payload per *path* suffices; the axis that matters there is
path/lookup coverage, not technique. Record as "technique-complete by fix shape".

### CWE-078 — OS command injection (Commandline / Shell quoting)

When the fix is an **unconditional quoter** (single-quote every fragment), it
neutralizes all metacharacters at once, so `;` vs `|` vs newline do NOT
discriminate — one breakout per **quoting-escape mechanism** is what matters:

- **T1 substitution** — `$(...)` / backtick inside a double-quoted fragment
- **T2 pre-quoted short-circuit** — payload already delimiter-wrapped so a
  "looks already quoted" fast path skips escaping (`"";cmd;#"`)
- **T3 delimiter-escape gap** — escaped-chars list omits the quote delimiter
  itself (only reproduces if the product actually leaves it unescaped)
- × per **injection point** that reaches the sink through a distinct code branch
  (argument vs executable vs working-directory), since the quoter may be applied
  differently per branch — this is the matrix plexus-utils-2017 now uses.

### CWE-022 — path traversal / zip-slip

Here "technique" and "path/vector" largely coincide, and the path-completeness
checklist (step 7) already enumerates them: relative `../`, absolute-path entry,
backslash separator, symlink entry, shared-prefix sibling (usually residual),
compound non-`..`-prefixed. Two techniques worth an explicit *technique* check
that the path checklist under-emphasizes, **but only where the fix is a string
check, not canonicalization, and only if they actually traverse the filesystem**
(most don't — document the negative):

- Unicode / fullwidth separator variants (U+FF3C etc.) — almost always inert
  (not an OS separator); test before believing.
- URL / double / triple encoding — only for HTTP-layer servers, and only if a
  second decode pass is actually reachable (usually it isn't).

Because a canonicalization-based fix (`getCanonicalPath`) collapses every
representation at once, technique diversity does NOT discriminate against it —
so for the many zip-slip projects whose fix canonicalizes, the set is
technique-complete once the path checklist is satisfied.

### CWE-079 — XSS / sanitizer bypass

When the fix is an **allow-list** (jolokia: JSONP callback must match
`^[$A-Z_][0-9A-Z_$]*$`), every injection technique fails the same allow-list →
technique-complete by fix shape. When the fix is a **parser/structural change**
(antisamy: disable CDATA parsing + strip markers), the techniques are the
distinct markup constructs that smuggle a live node past the sanitizer — those
are path-like and covered by the path audit.

---

## Per-project technique audit

Verdict: `complete-by-shape` = the fix neutralizes techniques wholesale, one
payload suffices · `gap→fixed` = a discriminating technique was missing, added ·
`gap→open` = missing, not yet added · `n/a` = CWE where technique ≡ path.

| Project | CWE | Fix shape | Techniques tested | Verdict |
|---|---|---|---|---|
| codecentric__spring-boot-admin CVE-2022-46166 | 094 | SpEL context restriction | T1 type-ref ✅, T2 reflection ✅ (round 5), T3 constructor ✅ (round 6) | **gap→fixed** |
| ff4j CVE-2022-44262 | 094 | reflection allow-list | class-name injection ✅ | complete-by-shape |
| asf__commons-text CVE-2022-42889 | 094 | remove lookups from defaults | script/dns/url × 4 overloads ✅ | complete-by-shape (lookup coverage is the axis, done) |
| plexus-utils CVE-2017-1000487 | 078 | unconditional single-quote | T1 subst ✅, T2 pre-quoted ✅ (arg+exec) | complete-by-shape (T3 delimiter-escape tested → not reproduced) |
| rhuss__jolokia CVE-2018-1000129 | 079 | callback allow-list regex | one payload ✅ | complete-by-shape |
| nahsra__antisamy CVE-2022-28367 | 079 | disable CDATA parse + strip | CDATA smuggling constructs ✅ | complete-by-shape (constructs ≡ path) |
| all CWE-022 projects | 022 | canonicalization (mostly) | see path checklist | n/a / complete-by-shape; residual set covers string-check fixes |

## Status: dataset is technique-complete

Every project is now technique-complete. **spring-boot-admin** was the one
open gap — its official `SimpleEvaluationContext` blocks all three RCE
techniques (T1 type-ref, T2 `Class.forName` reflection, T3 `new` constructor),
but a partial patch could blacklist `T(...)` and `Class.forName` while missing
the `new` operator, which our then-13-POV set would have scored 1.0. The T3
constructor POV (`new java.lang.ProcessBuilder(...).start()`, no `T(...)`/no
`Class.forName`) was added round 6 and certifies as fixPOV (reproduces
unpatched, blocked by the official fix). spring-boot-admin now carries 14 POVs
across all three techniques.

Everything else in the table is technique-complete **by the shape of its
official fix** — a broad control (canonicalization, allow-list, feature removal,
unconditional quoter) neutralizes every payload technique at once, so one
representative payload per path is sufficient and adding technique variants
would not discriminate against any plausible patch. That verdict is the audit
result, not an omission.

## How to continue this axis

For any new CWE class or fix added later: classify the **fix shape** first. If it
is a broad control (context restriction, unconditional transform, allow-list,
feature removal) it is likely technique-complete with one payload per path —
confirm and record. If it is a **specific filter** (a blacklist of names,
characters, or a single technique), enumerate the sibling techniques the broad-
control equivalent would also block, and add one POV per technique that (a)
certifies against the official fix and (b) passes the discrimination test.
