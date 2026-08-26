"""Ensemble judging: sample an LLM judge K times and stabilize the verdict.

A single-shot LLM judge is noisy — the same patch can score 68 on one pass and
76 on the next, and a borderline dimension can swing two whole points. That
variance is invisible when you only look once, and it quietly undermines every
number the dashboard reports.

Ensemble judging runs the *same* judge on the *same* input K times and reports
the distribution instead of a lucky draw: the median score, the spread, and how
often the samples agreed. The headline number becomes a median with a confidence
band, and each rubric dimension carries its own agreement signal so you can see
exactly where the judge was sure and where it was guessing.

The narrative (summary, rationales, issues) is taken from the *medoid* — the
single sample whose dimension scores sit closest to the per-dimension medians —
so the prose you read always corresponds to a real, internally consistent pass
rather than a Frankenstein of fragments from different samples.
"""
from __future__ import annotations

import statistics
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

# Cap on concurrent judge subprocesses per ensemble. Each sample is a blocking
# `claude -p` call; a handful in parallel collapses wall-time from K×one-shot to
# ~one-shot without hammering the API or the host.
MAX_CONCURRENCY = 3


def _dim_scores(sample: dict) -> dict:
    """Map dimension key -> integer score for one judge sample."""
    out = {}
    for d in sample.get("dimensions", []):
        score = d.get("score")
        if isinstance(score, bool):  # bool is an int subclass; never a score
            continue
        if isinstance(score, int):
            out[d.get("key")] = score
    return out


def _pstdev(xs: list) -> float:
    return round(statistics.pstdev(xs), 2) if len(xs) > 1 else 0.0


def _modal_agreement(values: list) -> float:
    """Fraction of samples that landed on the most common value."""
    if not values:
        return 0.0
    top = statistics.mode(values)
    return round(sum(1 for v in values if v == top) / len(values), 2)


def _confidence(score_stdev: float, band_agreement: float) -> str:
    """Coarse tier from headline-score dispersion + band agreement.

    Tuned for a 0–100 score: <=4 pts of scatter with unanimous banding is
    trustworthy; a two-band split or >8 pts of scatter is a coin toss.
    """
    if score_stdev <= 4.0 and band_agreement >= 0.99:
        return "high"
    if score_stdev <= 8.0 and band_agreement >= 0.6:
        return "medium"
    return "low"


def aggregate(samples: list, *, dim_labels: dict) -> dict:
    """Fold K judge samples into a distribution + a medoid pointer.

    Each sample is a fully-decorated eval result (``dimensions`` with integer
    scores, an ``overall`` block, and ``gates``). Returns the ensemble summary;
    ``medoid_index`` points at the representative sample for narrative reuse.
    """
    n = len(samples)
    per_sample = [_dim_scores(s) for s in samples]
    keys = [d.get("key") for d in samples[0].get("dimensions", [])]

    dim_stats = []
    medians: dict = {}
    for key in keys:
        scores = [ds[key] for ds in per_sample if key in ds]
        if not scores:
            continue
        med = statistics.median(scores)
        medians[key] = med
        dim_stats.append(
            {
                "key": key,
                "label": dim_labels.get(key, key),
                "median": round(med),
                "min": min(scores),
                "max": max(scores),
                "stdev": _pstdev(scores),
                "agreement": _modal_agreement(scores),
                "samples": scores,
            }
        )

    # Medoid: the sample whose dimension vector is closest (L1) to the medians.
    def l1(idx: int) -> float:
        ds = per_sample[idx]
        return sum(abs(ds[k] - medians[k]) for k in medians if k in ds)

    medoid_index = min(range(n), key=l1)

    overall_scores = [s.get("overall", {}).get("score", 0) for s in samples]
    overall_means = [s.get("overall", {}).get("mean", 0) for s in samples]
    bands = [s.get("overall", {}).get("band", "?") for s in samples]
    band_mode = statistics.mode(bands)
    band_agreement = round(sum(1 for b in bands if b == band_mode) / n, 2)
    score_stdev = _pstdev(overall_scores)

    gate_keys = list(samples[0].get("gates", {}).keys())
    gate_agreement = {
        g: round(sum(1 for s in samples if s.get("gates", {}).get(g)) / n, 2) for g in gate_keys
    }

    return {
        "samples": n,
        "overall": {
            "score_median": round(statistics.median(overall_scores)),
            "score_mean": round(statistics.fmean(overall_scores), 1),
            "score_min": min(overall_scores),
            "score_max": max(overall_scores),
            "score_stdev": score_stdev,
            "mean_median": round(statistics.median(overall_means), 2),
            "band_mode": band_mode,
            "band_agreement": band_agreement,
            "mean_dim_stdev": round(statistics.fmean([d["stdev"] for d in dim_stats]), 2) if dim_stats else 0.0,
        },
        "dimensions": dim_stats,
        "gate_agreement": gate_agreement,
        "per_sample": [
            {
                "score": s.get("overall", {}).get("score"),
                "band": s.get("overall", {}).get("band"),
                "gates_passed": s.get("overall", {}).get("gates_passed"),
            }
            for s in samples
        ],
        "confidence": _confidence(score_stdev, band_agreement),
        "medoid_index": medoid_index,
    }


def _run_samples(sample_fn: Callable[[Path], dict], sample_dirs: list) -> list:
    """Run each sample in its own out_dir, in parallel, tolerating failures.

    A sample that raises becomes ``None`` in the returned list (same position);
    callers filter those out. Isolating each sample's out_dir keeps their
    input.md / raw_stdout.txt from clobbering each other.
    """
    results: list = [None] * len(sample_dirs)

    def one(i: int) -> None:
        results[i] = sample_fn(sample_dirs[i])

    workers = min(MAX_CONCURRENCY, len(sample_dirs))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ensemble") as pool:
        futures = [pool.submit(one, i) for i in range(len(sample_dirs))]
        for f in futures:
            try:
                f.result()
            except Exception:  # noqa: BLE001 - one bad sample must not sink the ensemble
                pass
    return results


def run(
    *,
    out_dir: Path,
    samples: int,
    dim_labels: dict,
    sample_fn: Callable[[Path], dict],
) -> dict:
    """Produce one eval result, optionally stabilized over ``samples`` judges.

    ``sample_fn(out_dir)`` runs a single judge pass into ``out_dir`` and returns
    its decorated parsed result. At ``samples == 1`` this is exactly the legacy
    single-shot path (writes straight into ``out_dir``). At K > 1 the samples run
    in isolated ``out_dir/samples/<i>/`` dirs and the medoid result is returned
    with an added ``ensemble`` block carrying the distribution.
    """
    samples = max(1, min(int(samples), 5))
    if samples == 1:
        return sample_fn(out_dir)

    sample_dirs = []
    for i in range(1, samples + 1):
        d = out_dir / "samples" / str(i)
        d.mkdir(parents=True, exist_ok=True)
        sample_dirs.append(d)

    raw = _run_samples(sample_fn, sample_dirs)
    ok = [r for r in raw if r is not None]
    if not ok:
        raise RuntimeError(f"all {samples} ensemble samples failed")

    ens = aggregate(ok, dim_labels=dim_labels)
    ens["samples_attempted"] = samples
    result = ok[ens["medoid_index"]]
    result["ensemble"] = ens
    return result
