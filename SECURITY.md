# Security policy

P2Patch is research software that generates and runs exploits against
vulnerable software, inside containers, for the purpose of evaluating
vulnerability repair. Please use it only on code you are authorized to test.

## Reporting a vulnerability

If you find a security issue in this repository, or if you maintain a project
in the benchmark and want to discuss a finding, please **do not open a public
issue**. Email Sina Moradi Sabet (<sina.moradi4233@gmail.com>) or Mohsen
Iranmanesh (<mhsn.iranmanesh@gmail.com>) instead. We aim to respond within a
week.

## Responsible disclosure of benchmark findings

Building the benchmark uncovered attack paths that some projects' official CVE
fixes leave open. We report these gaps to the affected projects through their
security channels. Until a fix is available, the exploit artifacts for these
gaps are withheld from this repository; see
[benchmark/WITHHELD_ARTIFACTS.md](benchmark/WITHHELD_ARTIFACTS.md).
