#!/usr/bin/env python3
"""Transparent logging proxy for the Anthropic API — records per-call token usage.

    python3 usage_proxy.py --out /root/autosec-baselines/san2patch/usage.jsonl

San2Patch persists no token accounting of its own, and its paper reports $0.48/case, so we need a
comparable number. This gets it **without touching their code**: `langchain_anthropic` honours the
`ANTHROPIC_API_URL` environment variable (verified empirically — note it is *not*
`ANTHROPIC_BASE_URL`, which the raw SDK uses but LangChain overrides), so pointing that at this
proxy in `/app/.env` routes every call through here on its way to the real API.

Runs on the HOST, not in the container: the log then survives `docker rm`, and a container restart
does not take the proxy with it. Containers reach it at the docker bridge gateway (172.17.0.1).

Design constraints, in priority order:

1. **Never break a run.** Every logging step is wrapped; any failure is swallowed and the response
   is forwarded regardless. The proxy is in the critical path, so the only acceptable behaviour on
   an internal error is "still proxy the request".
2. **Do not buffer whole conversations in memory** beyond what one request needs.
3. **Never log prompt or completion text** — only counts. The bodies contain source code and, in
   this benchmark, exploit inputs; there is no reason to write them to a second place on disk.

Their code calls with streaming disabled (plain `chain.invoke`), so responses are single JSON
bodies carrying `usage: {input_tokens, output_tokens}`. Streaming responses are passed through
untouched and logged with null counts rather than being parsed.

Stdlib only.
"""
from __future__ import annotations

import argparse
import http.server
import json
import socketserver
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Overridable so the same proxy meters any provider: Anthropic, OpenAI, DeepSeek,
# Together, … . The response shapes differ (`usage.input_tokens` for Anthropic,
# `usage.prompt_tokens` for OpenAI-compatible APIs) and both are parsed below, so a
# new provider usually needs nothing here beyond pointing --upstream at it.
UPSTREAM = "https://api.anthropic.com"
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length"}

_lock = threading.Lock()
_out: Path | None = None
_stats = {"calls": 0, "logged": 0, "errors": 0}


def write_rec(rec: dict):
    """Append one JSONL record. Never raises."""
    global _out
    try:
        if _out is None:
            return
        rec.setdefault("ts", datetime.now(timezone.utc).astimezone().isoformat())
        with _lock:
            with _out.open("a") as fh:
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
        _stats["logged"] += 1
    except Exception:
        _stats["errors"] += 1


def record(model, usage, status, duration_ms, path):
    u = usage or {}
    write_rec({
        "kind": "call",
        "model": model,
        # Anthropic names these input_tokens/output_tokens; OpenAI-compatible providers
        # (OpenAI, DeepSeek, …) name them prompt_tokens/completion_tokens. Accept both so
        # one proxy meters every provider and metrics.py needs no per-provider branch.
        "input_tokens": u.get("input_tokens", u.get("prompt_tokens")),
        "output_tokens": u.get("output_tokens", u.get("completion_tokens")),
        "cache_read_tokens": u.get("cache_read_input_tokens",
                                   (u.get("prompt_tokens_details") or {}).get("cached_tokens")),
        "cache_write_tokens": u.get("cache_creation_input_tokens"),
        "status": status,
        "duration_ms": duration_ms,
        "path": path,
    })


def heartbeat(interval: int = 60):
    """Periodic liveness marker.

    Without this, a proxy that died at 14:32 and was restarted at 14:37 leaves no trace
    in usage.jsonl beyond an absence of calls — indistinguishable from a case that simply
    took a while between LLM calls. A heartbeat turns that ambiguity into a visible gap,
    which is what lets triage.py say "the proxy was down for this case" rather than guess.
    """
    while True:
        try:
            write_rec({"kind": "heartbeat", "calls": _stats["calls"],
                       "errors": _stats["errors"]})
        except Exception:
            pass
        threading.Event().wait(interval)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet; we keep our own log
        pass

    def _proxy(self):
        started = datetime.now()
        _stats["calls"] += 1
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None

            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
            req = urllib.request.Request(UPSTREAM + self.path, data=body,
                                         headers=headers, method=self.command)
            try:
                resp = urllib.request.urlopen(req, timeout=600)
                status, raw, rhdrs = resp.status, resp.read(), dict(resp.headers)
            except urllib.error.HTTPError as e:          # forward upstream errors verbatim
                status, raw, rhdrs = e.code, e.read(), dict(e.headers)

            # --- logging: strictly best-effort, never affects the response ---
            # `raw` is forwarded to the client byte-for-byte; we only ever decode a COPY.
            # The upstream body is normally gzip-encoded (the client's Accept-Encoding is
            # passed straight through), so it has to be decompressed before it will parse.
            model = usage = None
            try:
                if "application/json" in (rhdrs.get("Content-Type") or ""):
                    enc = (rhdrs.get("Content-Encoding") or "").lower()
                    payload = raw
                    if enc == "gzip":
                        import gzip
                        payload = gzip.decompress(raw)
                    elif enc == "deflate":
                        import zlib
                        payload = zlib.decompress(raw)
                    elif enc == "br":
                        import brotli  # type: ignore
                        payload = brotli.decompress(raw)
                    j = json.loads(payload)
                    model, usage = j.get("model"), j.get("usage")
            except Exception:
                pass
            record(model, usage, status,
                   int((datetime.now() - started).total_seconds() * 1000), self.path)

            self.send_response(status)
            for k, v in rhdrs.items():
                if k.lower() not in HOP_BY_HOP:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        except Exception as exc:                          # last resort: fail loudly to the client
            _stats["errors"] += 1
            # THE record that matters for triage: this call never reached Anthropic,
            # so any case failure in this window is ours, not the tool's.
            write_rec({"kind": "proxy_error", "error": str(exc)[:300], "path": self.path,
                       "duration_ms": int((datetime.now() - started).total_seconds() * 1000)})
            try:
                msg = json.dumps({"type": "error", "error": {
                    "type": "proxy_error", "message": f"usage_proxy: {exc}"}}).encode()
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
            except Exception:
                pass

    do_POST = do_GET = do_PUT = do_DELETE = _proxy

    def do_HEAD(self):                                    # health check
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    global _out, UPSTREAM
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="usage.jsonl to append to")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--heartbeat", type=int, default=30, help="liveness marker interval (s)")
    ap.add_argument("--upstream", default=UPSTREAM,
                    help="provider base URL, e.g. https://api.deepseek.com")
    a = ap.parse_args()
    UPSTREAM = a.upstream.rstrip("/")

    _out = Path(a.out)
    _out.parent.mkdir(parents=True, exist_ok=True)

    print(f"usage_proxy -> {UPSTREAM}")
    write_rec({"kind": "proxy_upstream", "upstream": UPSTREAM})
    print(f"  listening : {a.host}:{a.port}")
    print(f"  logging   : {_out}")
    print(f"  point the container at it with:  ANTHROPIC_API_URL=http://172.17.0.1:{a.port}")
    sys.stdout.flush()
    write_rec({"kind": "proxy_start", "port": a.port})
    threading.Thread(target=heartbeat, args=(a.heartbeat,), daemon=True).start()
    Server((a.host, a.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
