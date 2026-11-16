"use client";

import {
  CalendarClock,
  ExternalLink,
  FileCode2,
  Hash,
  Quote,
  FileText,
  SquareArrowOutUpRight,
  Crosshair,
} from "lucide-react";
import { VulnerabilityRecord } from "@/types/vulnerability";
import { Badge } from "@/components/ui/badge";
import { KevBadge, KevPanel } from "@/components/kev-badge";
import { CopyButton } from "@/components/copy-button";
import { CvssPopover } from "@/components/cvss-popover";
import { Tooltip } from "@/components/ui/tooltip";
import {
  formatQuickCopy,
  formatNamedCopy,
  formatMarkdownReport,
} from "@/lib/formatters";
import { cn, severityAccent, formatDate } from "@/lib/utils";

export function VulnCard({ vuln }: { vuln: VulnerabilityRecord }) {
  return (
    <article
      className={cn(
        "relative animate-fade-in overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 shadow-xl sm:p-6",
        "before:absolute before:inset-y-0 before:left-0 before:w-1",
        severityAccent(vuln.cvssMetrics.primary.severity)
      )}
    >
      {/* Header: ID, branded name, badges */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="font-mono text-xl font-bold tracking-tight text-zinc-100">
              {vuln.cveId}
            </h2>
            {vuln.brandedName && (
              <Badge className="border-purple-500/30 bg-purple-500/10 text-purple-300">
                {vuln.brandedName}
              </Badge>
            )}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <CvssPopover
              primary={vuln.cvssMetrics.primary}
              all={vuln.cvssMetrics.all}
            />
            {vuln.cisaKev.isKev && <KevBadge />}
          </div>
        </div>

        {/* Top-right actions: NVD link + quick CVE ID copy */}
        <div className="flex items-center gap-1.5">
          <Tooltip label="View on NVD">
            <a
              href={vuln.nvdUrl}
              target="_blank"
              rel="noopener noreferrer"
              aria-label={`View ${vuln.cveId} on NVD`}
              className="inline-flex items-center justify-center rounded-md border border-zinc-700 bg-zinc-800/60 p-2 text-zinc-300 transition-colors hover:border-indigo-500/40 hover:bg-indigo-500/10 hover:text-indigo-300"
            >
              <SquareArrowOutUpRight className="h-4 w-4" />
            </a>
          </Tooltip>
          <CopyButton
            value={vuln.cveId}
            toastLabel="CVE ID"
            tooltip="Copy CVE ID"
            icon={<Hash className="h-4 w-4" />}
          />
        </div>
      </div>

      {/* Description */}
      <p className="mt-4 text-sm leading-relaxed text-zinc-300">
        {vuln.description}
      </p>

      {/* Version-relevance evidence (version search only) */}
      {vuln.relevance?.matchedVersion && (
        <div className="mt-3 flex items-start gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
          <Crosshair className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
          <span>
            <span className="font-semibold">Affected version match</span>
            {vuln.relevance.via && (
              <>
                {" · "}
                <span className="rounded border border-emerald-500/40 px-1 py-0.5 text-[10px] font-medium uppercase tracking-wide text-emerald-200/90">
                  {vuln.relevance.via === "cpe"
                    ? "NVD Affected Products"
                    : "description"}
                </span>
              </>
            )}
            {vuln.relevance.evidence && (
              <>
                {" · "}
                <span className="font-mono text-emerald-200/90">
                  “{vuln.relevance.evidence}”
                </span>
              </>
            )}
          </span>
        </div>
      )}

      {/* Weaknesses */}
      {vuln.weaknesses.length > 0 && (
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
          {vuln.weaknesses.map((w) => (
            <Badge
              key={w}
              mono
              className="border-zinc-700 bg-zinc-800/60 text-zinc-300"
            >
              {w}
            </Badge>
          ))}
        </div>
      )}

      {/* Dates */}
      <div className="mt-4 flex flex-wrap gap-x-6 gap-y-1 text-xs text-zinc-500">
        <span className="inline-flex items-center gap-1.5">
          <CalendarClock className="h-3.5 w-3.5" />
          Published {formatDate(vuln.publishedDate)}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <CalendarClock className="h-3.5 w-3.5" />
          Modified {formatDate(vuln.lastModifiedDate)}
        </span>
      </div>

      {/* KEV detail panel */}
      {vuln.cisaKev.isKev && (
        <div className="mt-5">
          <KevPanel kev={vuln.cisaKev} />
        </div>
      )}

      {/* References */}
      {vuln.references.length > 0 && (
        <div className="mt-5">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">
            References
          </h3>
          <ul className="flex flex-col gap-1.5">
            {vuln.references.slice(0, 5).map((r, i) => (
              <li key={`${r.url}-${i}`}>
                <a
                  href={r.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex max-w-full items-center gap-1.5 text-sm text-indigo-400 hover:text-indigo-300 hover:underline"
                >
                  <ExternalLink className="h-3.5 w-3.5 flex-shrink-0" />
                  <span className="truncate">{r.source}</span>
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Copy action bar */}
      <div className="mt-6 flex flex-wrap gap-2 border-t border-zinc-800 pt-4">
        <CopyButton
          value={formatQuickCopy(vuln)}
          label="Reference"
          toastLabel="Reference line"
          tooltip="[CVE-ID] (CVSS - SEVERITY) - Description"
          icon={<Quote className="h-4 w-4" />}
        />
        {vuln.brandedName && (
          <CopyButton
            value={formatNamedCopy(vuln)}
            label="Named Reference"
            toastLabel="Named reference"
            tooltip="[CVE-ID / NAME] (CVSS - SEVERITY) - Description"
            icon={<FileText className="h-4 w-4" />}
          />
        )}
        <CopyButton
          value={formatMarkdownReport(vuln)}
          label="Markdown"
          toastLabel="Markdown report"
          tooltip="Structured Markdown block for reports & tickets"
          icon={<FileCode2 className="h-4 w-4" />}
          variant="solid"
        />
      </div>
    </article>
  );
}
