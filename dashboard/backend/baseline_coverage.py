"""Intention-to-treat held-out coverage for the published-baseline pages.

The paper scores every baseline under **intention-to-treat**: a subject that
carries a certified held-out suite counts in the denominator even when the system
shipped no patch for it, and is credited zero. Averaging only the subjects that
produced a scoreable patch answers a different, more generous question -- "how good
are the patches it *did* ship?" -- and gives a materially higher number. San2Patch's
fix-closed coverage reads 0.717 that way and 0.608 under the policy the paper
reports; LoopRepair's reads 0.437 and 0.325. The numerators are identical, so this
is purely a denominator choice, and shipping the generous one next to a paper that
reports the strict one invites a reader to compute a third number that appears in
neither.

The denominator is therefore

    n = scored + zero_credited

where ``scored`` are the subjects with a numeric score (each contributing that
score) and ``zero_credited`` are the subjects that carry a certified suite of this
family but for which the system produced no patch (each contributing zero).

Four things are deliberately **excluded** rather than credited zero, because each
would charge a system for something that is not a failed repair:

* a subject outside this benchmark (no ``project_info.csv`` row);
* a subject with no certified suite of that family -- there is nothing to measure,
  so counting it would penalise a system for our own curation gaps;
* a subject that was measured but is unscoreable (harness or build error, ``null``
  score) -- an unmeasured subject is not a failed repair, which is the same rule
  the pipeline's own fixPOV stage applies to an ``errored`` POV;
* a non-attempt: an attempt superseded by a later successful run of the same case,
  and a subject the system never attempted at all (PatchAgent's ``gnubug-19784``,
  whose harness cannot run here).

``mean_scored_only`` is kept alongside so the two policies stay visibly distinct in
the payload rather than one silently replacing the other.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

import config

#: Which curated suite directory backs each family name.
_SUITE_DIR = {
    "fixpov": lambda: config.fix_povs_dir(),
    "respov": lambda: config.residual_povs_dir(),
}


def has_certified_suite(family: str, project_slug: Optional[str]) -> bool:
    """Whether ``project_slug`` carries a curated suite of ``family``.

    Presence of the manifest is the test, not its contents: certification is
    enforced where the suite is *executed* (``fix_pov.evaluate_manifest`` checks
    ``validation.certified`` and the content fingerprint). Re-deriving it here would
    duplicate that logic in a module whose only job is to count denominators.
    """
    if not project_slug:
        return False
    root = _SUITE_DIR.get(family)
    if root is None:
        return False
    return (root() / project_slug / "manifest.json").is_file()


def summarize(
    scores: Sequence[float],
    zero_credited: int,
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """The coverage headline for one baseline and one oracle family.

    ``scores`` are the numeric per-subject scores; ``zero_credited`` is how many
    further subjects carry a certified suite but got no patch. Returns ``None``-free
    counts plus both means, so a caller never has to decide which policy the single
    ``mean_score`` key meant.
    """
    scored = len(scores)
    total = float(sum(scores))
    n = scored + max(0, int(zero_credited))
    out: Dict[str, Any] = {
        "scored": scored,
        "zero_credited": max(0, int(zero_credited)),
        # The paper's denominator, and what the pages render.
        "n": n,
        "fully_blocked": sum(1 for s in scores if s >= 1.0),
        "score_sum": round(total, 6),
        "mean_score": round(total / n, 4) if n else None,
        "mean_scored_only": round(total / scored, 4) if scored else None,
        "policy": "intention-to-treat",
    }
    if extra:
        out.update(extra)
    return out


def zero_credited_from_cases(
    family: str,
    cases: Iterable[Dict[str, Any]],
    *,
    slug_of,
    is_non_attempt=lambda case: False,
) -> int:
    """Count the no-patch subjects that belong in the denominator.

    ``cases`` are the subjects the baseline produced no scoreable patch for.
    ``slug_of`` maps one to its dataset project slug (``None`` if it is outside this
    benchmark, which drops it), and ``is_non_attempt`` drops the superseded and
    never-attempted ones.
    """
    n = 0
    for case in cases:
        if is_non_attempt(case):
            continue
        if has_certified_suite(family, slug_of(case)):
            n += 1
    return n
