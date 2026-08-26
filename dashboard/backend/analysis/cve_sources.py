"""Deterministic multi-source CVE fetchers for the CVE Research agent.

Every fetcher is defensive: network failures return None / [] rather than
raising, so partial results still flow through. Large whole-dataset blobs
(CISA KEV, Metasploit index, Exploit-DB CSV) are downloaded once and cached.
"""
from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
from typing import Optional

import httpx

import config

CACHE = config.CACHE_DIR / "cve_sources"
_UA = {"User-Agent": "p2patch-lab/0.1"}


def _get_json(url: str, timeout: float = 20.0, headers: Optional[dict] = None):
    try:
        r = httpx.get(url, timeout=timeout, headers={**_UA, **(headers or {})}, follow_redirects=True)
        if r.status_code != 200:
            return None
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def _get_text(url: str, timeout: float = 20.0) -> Optional[str]:
    try:
        r = httpx.get(url, timeout=timeout, headers=_UA, follow_redirects=True)
        return r.text if r.status_code == 200 else None
    except httpx.HTTPError:
        return None


def _cached(name: str, url: str, timeout: float = 60.0) -> Optional[str]:
    path = CACHE / name
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace")
    text = _get_text(url, timeout=timeout)
    if text is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def _year(cve: str) -> str:
    parts = cve.split("-")
    return parts[1] if len(parts) >= 2 else ""


def _num(cve: str) -> str:
    # "CVE-2018-9159" -> "2018-9159"
    return cve[4:] if cve.upper().startswith("CVE-") else cve


# --- Tier 1: canonical metadata --------------------------------------------

def fetch_nvd(cve: str) -> Optional[dict]:
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else None
    data = _get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}", headers=headers)
    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
        return None
    obj = vulns[0].get("cve", {})
    desc = next((d["value"] for d in obj.get("descriptions", []) if d.get("lang") == "en"), "")
    cvss = None
    metrics = obj.get("metrics", {})
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(k):
            entry = metrics[k][0]
            d = entry.get("cvssData", {})
            cvss = {
                "version": d.get("version"),
                "score": d.get("baseScore"),
                "severity": d.get("baseSeverity") or entry.get("baseSeverity"),
                "vector": d.get("vectorString"),
            }
            break
    refs = [{"url": r.get("url"), "tags": r.get("tags", [])} for r in obj.get("references", [])]
    return {
        "description": desc,
        "cvss": cvss,
        "published": obj.get("published"),
        "references": refs,
        "exploit_refs": [r["url"] for r in refs if "Exploit" in (r.get("tags") or [])],
    }


def fetch_osv(ghsa: str, cve: str) -> Optional[dict]:
    for ident in (ghsa, cve):
        if not ident:
            continue
        d = _get_json(f"https://api.osv.dev/v1/vulns/{ident}")
        if not d:
            continue
        fixed = []
        for aff in d.get("affected", []):
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if ev.get("fixed"):
                        fixed.append(ev["fixed"])
        return {"aliases": d.get("aliases", []), "fixed_versions": sorted(set(fixed)), "summary": d.get("summary")}
    return None


def fetch_ghsa(ghsa: str) -> Optional[dict]:
    if not ghsa:
        return None
    d = _get_json(f"https://api.github.com/advisories/{ghsa}", headers={"Accept": "application/vnd.github+json"})
    if not d:
        return None
    return {
        "summary": d.get("summary"),
        "severity": d.get("severity"),
        "cvss": (d.get("cvss") or {}).get("score"),
        "html_url": d.get("html_url"),
        "references": d.get("references", []),
    }


def fetch_kev(cve: str) -> dict:
    text = _cached("kev.json", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if not text:
        return {"known_exploited": False}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"known_exploited": False}
    for v in data.get("vulnerabilities", []):
        if v.get("cveID") == cve:
            return {
                "known_exploited": True,
                "date_added": v.get("dateAdded"),
                "ransomware": v.get("knownRansomwareCampaignUse"),
                "name": v.get("vulnerabilityName"),
            }
    return {"known_exploited": False}


# --- Tier 3: locate an actual exploit (curated -> aggregated) --------------

def find_metasploit(cve: str) -> list:
    text = _cached(
        "msf_modules.json",
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
    )
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    num = _num(cve)
    hits = []
    for key, mod in data.items():
        refs_str = json.dumps(mod.get("references", []))
        if num in refs_str and "CVE" in refs_str:
            path = (mod.get("path") or "").lstrip("/")
            hits.append(
                {
                    "source": "metasploit",
                    "kind": "metasploit",
                    "name": mod.get("fullname") or key,
                    "title": mod.get("name"),
                    "url": f"https://github.com/rapid7/metasploit-framework/blob/master/{path}" if path else None,
                    "confidence": "high",
                }
            )
    return hits[:3]


def find_exploitdb(cve: str) -> list:
    text = _cached("edb.csv", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv")
    if not text:
        return []
    num = _num(cve)
    hits = []
    for row in csv.DictReader(io.StringIO(text)):
        if num in (row.get("codes") or ""):
            hits.append(
                {
                    "source": "exploit-db",
                    "kind": "exploit-db",
                    "name": row.get("description"),
                    "url": f"https://www.exploit-db.com/exploits/{row.get('id')}",
                    "file": row.get("file"),
                    "confidence": "high",
                }
            )
    return hits[:3]


def find_nuclei(cve: str) -> list:
    year = _year(cve)
    url = f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/{year}/{cve}.yaml"
    text = _get_text(url)
    if not text:
        return []
    return [
        {
            "source": "nuclei",
            "kind": "nuclei",
            "name": f"{cve} nuclei template",
            "url": f"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/{year}/{cve}.yaml",
            "confidence": "medium",
            "content": text[:4000],
        }
    ]


def find_poc_repos(cve: str) -> list:
    """Aggregated candidate repos (nomi-sec) — NOT trusted; the judge validates."""
    year = _year(cve)
    data = _get_json(f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json")
    if not data:
        return []
    ranked = sorted(data, key=lambda r: int(r.get("stargazers_count", 0) or 0), reverse=True)
    out = []
    for repo in ranked[:6]:
        out.append(
            {
                "source": "github",
                "kind": "poc-repo",
                "name": repo.get("full_name"),
                "url": repo.get("html_url"),
                "description": repo.get("description"),
                "stars": repo.get("stargazers_count"),
                "created": repo.get("created_at"),
                "confidence": "candidate",
            }
        )
    return out


def find_trickest(cve: str) -> Optional[str]:
    year = _year(cve)
    return _get_text(f"https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve}.md")
