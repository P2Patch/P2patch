#!/usr/bin/env python3
"""Register a new model in San2Patch, idempotently, inside the container.

    docker cp add_model.py san2patch:/tmp/
    docker exec san2patch python3 /tmp/add_model.py --list
    docker exec san2patch python3 /tmp/add_model.py deepseek-chat

WHY A SCRIPT AND NOT A .patch: registering a model touches three places in two files —
a `Literal[...]` in utils/enum.py, and both a click.Choice list and an if/elif chain in
run.py — none of which have stable line numbers across upstream revisions. A diff breaks
on the first unrelated upstream edit and fails in a way that looks like the model is
unsupported. This edits by anchor string instead, refuses to double-apply, and verifies
by asking the CLI whether it now accepts the model.

All four stock Anthropic model ids in this image are retired, which is why
claude-haiku-4.5 had to be added at all (see 0001-add-claude-haiku-4-5.patch); expect the
OpenAI and Gemini ones to retire the same way.

Adding a provider that is NOT OpenAI/Anthropic/Google-compatible needs a new Patcher
class as well — this script only wires up models reachable through an existing one.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

APP = Path("/app")
ENUM = APP / "san2patch/utils/enum.py"
RUN = APP / "run.py"

# alias -> (patcher class, module, extra import needed)
# DeepSeek speaks the OpenAI wire format, so it rides on OpenAIPatcher with a different
# base_url; nothing about the ToT logic changes.
KNOWN = {
    "deepseek-chat": ("DeepSeekChatPatcher", "san2patch.patching.llm.openai_llm_patcher", True),
    "deepseek-reasoner": ("DeepSeekReasonerPatcher", "san2patch.patching.llm.openai_llm_patcher", True),
}

DEEPSEEK_CLASSES = '''

class DeepSeekPatcher(OpenAIPatcher):
    """DeepSeek via its OpenAI-compatible endpoint.

    Only the credentials and base URL differ; structured output, temperature and
    logprob handling are inherited from OpenAIPatcher unchanged.
    """

    name = "DeepSeek Base"
    vendor = "DeepSeek"

    def __init__(self, prompt=None, model_name: str = "deepseek-chat", **kwargs):
        import os
        from dotenv import load_dotenv
        load_dotenv(override=True)
        kwargs.setdefault("base_url", os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com"))
        # OpenAIPatcher reads OPENAI_API_KEY; point it at the DeepSeek credential.
        os.environ["OPENAI_API_KEY"] = os.getenv("DEEPSEEK_API_KEY", "")
        super().__init__(prompt, model_name=model_name, **kwargs)


class DeepSeekChatPatcher(DeepSeekPatcher):
    name = "DeepSeek Chat"

    def __init__(self, prompt=None, **kwargs):
        super().__init__(prompt, model_name="deepseek-chat", **kwargs)


class DeepSeekReasonerPatcher(DeepSeekPatcher):
    name = "DeepSeek Reasoner"

    def __init__(self, prompt=None, **kwargs):
        super().__init__(prompt, model_name="deepseek-reasoner", **kwargs)
'''


def edit(path: Path, apply, label: str) -> bool:
    src = path.read_text()
    out = apply(src)
    if out is None:
        print(f"  = {label}: already present")
        return False
    path.write_text(out)
    print(f"  + {label}: added")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("model", nargs="?", help=f"one of: {', '.join(KNOWN)}")
    ap.add_argument("--list", action="store_true", help="show currently registered models")
    a = ap.parse_args()

    if a.list or not a.model:
        cur = re.search(r"MODEL_LIST\s*=\s*Literal\[(.*?)\]", ENUM.read_text(), re.S)
        print("registered models:")
        for m in re.findall(r'"([^"]+)"', cur.group(1) if cur else ""):
            print(f"  {m}")
        print(f"\naddable by this script: {', '.join(KNOWN)}")
        return 0

    if a.model not in KNOWN:
        print(f"unknown model {a.model!r}; addable: {', '.join(KNOWN)}", file=sys.stderr)
        return 2
    cls, module, needs_classes = KNOWN[a.model]
    print(f"registering {a.model} -> {cls}")

    # 1. the Patcher classes themselves
    if needs_classes:
        edit(APP / "san2patch/patching/llm/openai_llm_patcher.py",
             lambda s: None if "class DeepSeekPatcher" in s else s + DEEPSEEK_CLASSES,
             "openai_llm_patcher.py: DeepSeek classes")

    # 2. the Literal that types the --model value
    edit(ENUM,
         lambda s: None if f'"{a.model}"' in s
         else s.replace("MODEL_LIST = Literal[\n", f'MODEL_LIST = Literal[\n    "{a.model}",\n', 1),
         f"enum.py: {a.model} in MODEL_LIST")

    def run_py(s: str):
        if f'model == "{a.model}"' in s:
            return None
        # import
        s = s.replace("from san2patch.patching.patcher import",
                      f"from {module} import {cls}\nfrom san2patch.patching.patcher import", 1)
        # click.Choice list — anchor on the first entry, which is stable
        s = s.replace('        [\n            "gpt-4o",',
                      f'        [\n            "{a.model}",\n            "gpt-4o",', 1)
        # dispatch chain — insert before the final else so ordering never matters
        s = s.replace('    else:\n        raise ValueError(f"Model {model} not found")',
                      f'    elif model == "{a.model}":\n        model_class = {cls}\n'
                      '    else:\n        raise ValueError(f"Model {model} not found")', 1)
        return s

    edit(RUN, run_py, f"run.py: import, choice and dispatch for {a.model}")

    # 3. Verify against the CLI rather than trusting the edits.
    print("\nverifying...")
    r = subprocess.run(["python", "run.py", "Final", "run-patch", "--help"],
                       cwd=APP, capture_output=True, text=True)
    if a.model in r.stdout or a.model in r.stderr:
        print(f"  [OK] the CLI now offers {a.model}")
        return 0
    print(f"  [FAIL] {a.model} not visible to the CLI; edits may not have applied", file=sys.stderr)
    print((r.stderr or r.stdout)[-800:], file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
