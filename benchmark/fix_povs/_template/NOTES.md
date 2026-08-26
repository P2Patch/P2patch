# <project_slug> — <CVE> (<short name>)

- **CWE:** <CWE-ID>
- **Advisory:** <GHSA> / <CVE>
- **Vulnerable version:** <version>
- **Fix commit:** <fix_commit_ids>

## Root cause / sink

Describe the sink (`file:method`) and the trust boundary — where
attacker-controlled input reaches it without the missing check.

## Path coverage

List every source-to-sink path a complete fix must block, and which POV covers
each. Explain why the set is exhaustive (alternate encodings, sibling call
sites, etc.). Cross-reference the finder alert traces.

## Official fix (the "after" oracle)

Describe what `official_fix.patch` changes and how it maps to the upstream fix
commit.

## Certification

```bash
python -m security_pipeline fixpov validate --project <project_slug>
```
