"use client";

import { useEffect, useRef, useState } from "react";
import { ChevronDown, Layers } from "lucide-react";
import { CvssMetric } from "@/types/vulnerability";
import { cn, severityClasses } from "@/lib/utils";

/**
 * Minimalist interactive CVSS badge.
 *
 * Shows only the highest-version score as a prominent badge (e.g.
 * "9.8 CRITICAL · v4.0"). On hover or click it reveals a discreet popover
 * listing every available CVSS version (4.0 → 2.0) with its score, severity,
 * and vector string — keeping the card uncluttered.
 */
export function CvssPopover({
  primary,
  all,
}: {
  primary: CvssMetric;
  all: CvssMetric[];
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const scoreLabel = primary.score > 0 ? primary.score.toFixed(1) : "N/A";
  const hasMore = all.length > 1;

  // Close on outside click / Escape.
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div
      ref={ref}
      className="relative inline-flex"
      onMouseEnter={() => hasMore && setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <button
        type="button"
        onClick={() => hasMore && setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup={hasMore}
        className={cn(
          "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-xs font-medium tracking-wide transition-colors",
          severityClasses(primary.severity),
          hasMore && "cursor-pointer hover:brightness-125"
        )}
      >
        CVSS {scoreLabel} · {primary.severity}
        <span className="opacity-70">v{primary.version}</span>
        {hasMore && (
          <ChevronDown
            className={cn(
              "h-3 w-3 transition-transform",
              open && "rotate-180"
            )}
          />
        )}
      </button>

      {open && hasMore && (
        <div
          role="dialog"
          className="absolute left-0 top-full z-40 mt-2 w-72 animate-fade-in rounded-lg border border-zinc-700 bg-zinc-900 p-3 shadow-2xl"
        >
          <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-zinc-400">
            <Layers className="h-3.5 w-3.5" />
            All CVSS Metrics
          </div>
          <ul className="flex flex-col gap-2">
            {all.map((m) => (
              <li
                key={m.version}
                className="rounded-md border border-zinc-800 bg-zinc-950/60 p-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-zinc-400">
                    v{m.version}
                  </span>
                  <span
                    className={cn(
                      "rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold",
                      severityClasses(m.severity)
                    )}
                  >
                    {m.score > 0 ? m.score.toFixed(1) : "N/A"} · {m.severity}
                  </span>
                </div>
                {m.vectorString && (
                  <code className="mt-1.5 block break-all font-mono text-[11px] leading-relaxed text-zinc-500">
                    {m.vectorString}
                  </code>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
