import { useEffect, useState } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { PUBLISHED, api } from "./api";
import type { PublishedMeta } from "./types";

function BrandMark() {
  // A source→sink glyph: two nodes wired through a center — the pipeline in miniature.
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden>
      <circle cx="4" cy="11" r="2.4" className="fill-info" />
      <line x1="6" y1="11" x2="16" y2="11" className="stroke-iris" strokeWidth="1.4" />
      <circle cx="11" cy="11" r="1.6" className="fill-iris" />
      <circle cx="18" cy="11" r="2.4" className="fill-fail" />
    </svg>
  );
}

function PublishedBadge() {
  const [meta, setMeta] = useState<PublishedMeta | null>(null);
  useEffect(() => {
    api.meta().then(setMeta).catch(() => setMeta(null));
  }, []);
  const when = meta?.generated_at
    ? new Date(meta.generated_at).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })
    : null;
  return (
    <div
      className="ml-auto flex items-center gap-2 font-mono text-2xs text-txt-faint"
      title="A read-only snapshot of the experiments — the live pipeline runs on the team's machine."
    >
      <span className="inline-flex items-center gap-1.5 rounded-full border border-hairline bg-elevated px-2 py-0.5">
        <span className="h-1.5 w-1.5 rounded-full bg-pass" />
        published snapshot
      </span>
      {meta && <span className="hidden sm:inline">{meta.run_count} runs · {meta.distinct_cves} CVEs{when ? ` · ${when}` : ""}</span>}
    </div>
  );
}

export function App() {
  const loc = useLocation();
  const onExperiments = loc.pathname === "/" || loc.pathname.startsWith("/runs");
  const onLive = loc.pathname.startsWith("/live");
  const onOtherProjects = loc.pathname.startsWith("/other-projects");
  const onSan2Patch = loc.pathname.startsWith("/san2patch");
  const onResidual = loc.pathname.startsWith("/residual-audit");
  const onPatchAgent = loc.pathname.startsWith("/patchagent");
  return (
    <div className="min-h-full">
      <header className="sticky top-0 z-20 border-b border-hairline bg-ink/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-6 px-6">
          <Link to="/" className="focusable flex items-center gap-2.5">
            <BrandMark />
            <span className="font-display text-sm font-bold tracking-tight text-txt">
              P2Patch<span className="text-txt-faint"> Lab</span>
            </span>
          </Link>
          <nav className="flex items-center gap-1 text-sm">
            <Link
              to="/"
              className={`focusable rounded-md px-3 py-1.5 ${
                onExperiments ? "bg-elevated text-txt" : "text-txt-dim hover:text-txt"
              }`}
            >
              Experiments
            </Link>
            <Link
              to="/other-projects"
              className={`focusable rounded-md px-3 py-1.5 ${
                onOtherProjects ? "bg-elevated text-txt" : "text-txt-dim hover:text-txt"
              }`}
            >
              Other projects
            </Link>
            <Link
              to="/residual-audit"
              className={`focusable rounded-md px-3 py-1.5 ${
                onResidual ? "bg-elevated text-txt" : "text-txt-dim hover:text-txt"
              }`}
            >
              Residual audit
            </Link>
            <Link
              to="/san2patch"
              className={`focusable rounded-md px-3 py-1.5 ${
                onSan2Patch ? "bg-elevated text-txt" : "text-txt-dim hover:text-txt"
              }`}
            >
              San2Patch
            </Link>
            <Link
              to="/patchagent"
              className={`focusable rounded-md px-3 py-1.5 ${
                onPatchAgent ? "bg-elevated text-txt" : "text-txt-dim hover:text-txt"
              }`}
            >
              PatchAgent
            </Link>
            {/* Live is a control surface (spawns Docker/Claude) — absent in the published snapshot. */}
            {!PUBLISHED && (
              <Link
                to="/live"
                className={`focusable flex items-center gap-1.5 rounded-md px-3 py-1.5 ${
                  onLive ? "bg-elevated text-txt" : "text-txt-dim hover:text-txt"
                }`}
              >
                <span className="h-1.5 w-1.5 rounded-full bg-iris" />
                Live
              </Link>
            )}
          </nav>
          {PUBLISHED ? (
            <PublishedBadge />
          ) : (
            <div className="ml-auto font-mono text-2xs text-txt-faint">exploit · patch · verify</div>
          )}
        </div>
      </header>
      <main>
        <Outlet />
      </main>
    </div>
  );
}
