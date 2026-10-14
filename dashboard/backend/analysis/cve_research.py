"""CVE Research agent: fetch canonical CVE metadata + locate a public exploit.

Deterministic multi-source fetch (NVD/OSV/GHSA/KEV + Metasploit/Exploit-DB/
Nuclei/PoC repos) followed by an LLM genuineness judge over the noisy aggregated
candidates. Persists ground_truth/cve.json and ground_truth/official_exploit.json
so the Exploitation Analysis agent can compare our POV to the official exploit.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import base, cve_sources

AGENT = "cve_research"
_HERE = Path(__file__).resolve().parent


def _cap(text: str, limit: int = 4000) -> str:
    if text and len(text) > limit:
        return text[:limit] + f"\n… [truncated]"
    return text or ""


def _render_input(cve: str, gt: dict, metadata: dict, curated: list, candidates: list, trickest: str) -> str:
    parts = [
        "# CVE research task\n",
        f"**CVE:** {cve}  **CWE:** {gt.get('cwe_id')} — {gt.get('cwe_name')}",
        f"**Affected product / repo:** {gt.get('project_slug')} — {gt.get('repo')}",
        f"**Advisory:** {gt.get('advisory_id')}\n",
        "## Canonical metadata (NVD / OSV / GHSA / KEV)",
        "```json",
        _cap(json.dumps(metadata, indent=2), 6000),
        "```\n",
        "## Curated exploit hits (Metasploit / Exploit-DB / Nuclei — trustworthy)",
        "```json",
        _cap(json.dumps(curated, indent=2), 4000),
        "```\n",
        "## Aggregated candidate repos (nomi-sec — VALIDATE each)",
        "```json",
        _cap(json.dumps(candidates, indent=2), 4000),
        "```\n",
        "## trickest curated links (markdown, if any)",
        _cap(trickest or "(none)", 2500),
        "\nJudge genuineness, pick best_exploit, and summarize. Return ONLY the JSON.",
    ]
    return "\n".join(parts)


def research(run_id: str, run_dir: Path, gt: dict) -> dict:
    cve = gt.get("cve_id", "")
    ghsa = gt.get("advisory_id", "")

    metadata = {
        "nvd": cve_sources.fetch_nvd(cve),
        "osv": cve_sources.fetch_osv(ghsa, cve),
        "ghsa": cve_sources.fetch_ghsa(ghsa),
        "kev": cve_sources.fetch_kev(cve),
    }
    curated = (
        cve_sources.find_metasploit(cve)
        + cve_sources.find_exploitdb(cve)
        + cve_sources.find_nuclei(cve)
    )
    candidates = cve_sources.find_poc_repos(cve)
    trickest = cve_sources.find_trickest(cve)

    out_dir = base.analysis_dir(run_dir, AGENT)
    input_md = _render_input(cve, gt, metadata, curated, candidates, trickest)
    system_prompt = (_HERE / "prompts" / "cve_research.md").read_text(encoding="utf-8")
    schema_json = (_HERE / "schemas" / "cve_research.json").read_text(encoding="utf-8")
    judge = base.run_claude_json(
        agent_name="cve_research",
        system_prompt=system_prompt,
        schema_json=schema_json,
        input_md=input_md,
        run_dir=run_dir,
        out_dir=out_dir,
        effort="medium",
    )

    result = {
        "cve_id": cve,
        "advisory_id": ghsa,
        "repo": gt.get("repo"),
        "metadata": metadata,
        "kev": metadata["kev"],
        "curated_exploits": curated,
        "candidate_repos": candidates,
        "trickest_present": bool(trickest),
        "judge": judge,
    }

    # Persist for cross-agent use (Exploitation Analysis official comparison).
    gt_dir = run_dir / "analysis" / "ground_truth"
    gt_dir.mkdir(parents=True, exist_ok=True)
    (gt_dir / "cve.json").write_text(json.dumps({"metadata": metadata}, indent=2), encoding="utf-8")
    (gt_dir / "official_exploit.json").write_text(
        json.dumps(
            {
                "best_exploit": judge.get("best_exploit"),
                "summary": judge.get("known_exploitation_summary"),
                "curated": curated,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return result


def start(run_id: str, run_dir: Path, gt: dict, *, force: bool = False) -> dict:
    return base.run_in_background(run_dir, AGENT, lambda: research(run_id, run_dir, gt), force=force)


def official_exploit(run_dir: Path) -> dict | None:
    """Read the persisted official exploit (if CVE research has run)."""
    path = run_dir / "analysis" / "ground_truth" / "official_exploit.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
