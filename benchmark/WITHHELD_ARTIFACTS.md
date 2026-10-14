# Withheld artifacts

Some of the exploit artifacts behind the P2Patch paper are **not** included in
this public release. This page explains what is withheld, why, what you can
still reproduce, and when the withheld material will be published.

## Why

VulnRepairBench contains two families of proof-of-vulnerability (PoV) suites:

- **Fix-closed PoVs** exercise attack paths that the official upstream fix
  closes. They target vulnerabilities that are already public and fixed, so
  publishing them adds no new risk.
- **Residual PoVs** exercise attack paths that the official fix *leaves open*.
  Some of those paths were later closed by upstream, but others still reproduce
  against the projects' current code.

A working exploit for a path that is still open in a maintained project is a
live vulnerability, not a benchmark test. Publishing it before the affected
project ships a fix would put that project's users at risk. We have reported
these gaps to the affected projects and withhold the corresponding artifacts
until a fix is available.

## What is withheld

We publish a residual suite only when **every** PoV in it targets a path that
upstream has since closed in its own code, or that never shipped in a release.
Everything else is withheld, whatever the reason it is not yet confirmed closed.

| Artifact | In the paper | Public here | Withheld |
|---|---:|---:|---:|
| Residual suites | 40 suites, 66 PoVs | 22 suites, 36 PoVs | 18 suites, 30 PoVs |
| Fix-closed suites | 101 suites, 324 PoVs | 97 suites, 308 PoVs | 4 suites, 16 PoVs |

The 18 withheld residual suites break down by their upstream status:

| Upstream status | Suites |
|---|---:|
| Still open in upstream's current code | 15 |
| Not yet determined (needs manual analysis) | 1 |
| Disputed by the maintainers (outside their threat model) | 1 |
| Not a sound instrument (excluded from scoring) | 1 |

The withheld material is:

- the residual suites themselves (PoV sources, run scripts, manifests, and the
  official-fix patches they are certified against), with their audit dossiers
  in `residual_povs/reports/` and their re-execution records in
  `residual_povs/verification/`;
- **four complete fix-closed suites** whose harnesses or fixtures also drive a
  withheld residual path. They will return once the residual logic is
  separated out and the suites are re-certified.

We deliberately do not list which suites are withheld: the list would itself
announce which official fixes still contain an open gap. The benchmark's
dataset tables (`dataset/`), Dockerfiles, and alerts still cover all 101
subjects.

## What you can still reproduce

- **Every pipeline run.** The pipeline, prompts, configurations, Dockerfiles
  and alerts for all 101 subjects are public, so any run in the paper can be
  repeated.
- **Most of the scoring.** Fix-closed scoring works on 97 subjects and residual
  scoring on 22, using the scripts in this repository.
- **The paper's own numbers.** These were computed with the complete suites.
  The per-subject scores for every subject, including the withheld ones, are
  reported in the paper's appendix tables, and the archived pipeline runs
  linked from the [usage guide](../docs/USAGE.md) contain the recorded results.

If you score with the public suites only, your fix-closed and residual
averages will be computed over fewer subjects than the paper's and will
therefore differ from them.

## When the withheld material will be released

We will publish a withheld suite once the affected project has released a fix
for the path it exercises, or once the maintainers agree that publishing it
does not put users at risk. Released suites will be added back to this
repository, and this page will be updated.

## Access and contact

- **Maintainers of an affected project** who want the full reproduction details
  for their own project can contact us, and we will share them privately.
- **Researchers** who need the withheld suites to reproduce the paper's results
  can also contact us. We consider each request individually and may wait until
  the relevant fixes have shipped.
- **Security issues in this repository** should be reported privately as
  described in [SECURITY.md](../SECURITY.md), not in public issues.

Contact: Sina Moradi Sabet (<sina.moradi4233@gmail.com>) or Mohsen Iranmanesh
(<mhsn.iranmanesh@gmail.com>).
