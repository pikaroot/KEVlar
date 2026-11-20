"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ShieldCheck,
  Terminal,
  AlertTriangle,
  SearchX,
  CalendarRange,
} from "lucide-react";
import { SearchBar } from "@/components/search-bar";
import { VulnCard } from "@/components/vuln-card";
import { EolBanner } from "@/components/eol-banner";
import { SkeletonCard } from "@/components/skeleton-card";
import { LookupResponse } from "@/types/vulnerability";

async function lookup(query: string, year: string): Promise<LookupResponse> {
  const params = new URLSearchParams({ q: query });
  if (year) params.set("year", year);
  const res = await fetch(`/api/lookup?${params.toString()}`);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data?.error || `Lookup failed (${res.status}).`);
  }
  return data as LookupResponse;
}

const CURRENT_YEAR = new Date().getFullYear();
const YEAR_OPTIONS = Array.from(
  { length: CURRENT_YEAR - 1998 },
  (_, i) => String(CURRENT_YEAR - i)
);

const RESOLVED_LABEL: Record<LookupResponse["resolvedVia"], string> = {
  "cve-id": "Resolved by CVE identifier",
  alias: "Resolved via alias dictionary",
  keyword: "Resolved by keyword search",
  version: "Ranked by affected-version relevance",
};

export default function Home() {
  const [query, setQuery] = useState<string | null>(null);
  const [year, setYear] = useState<string>("");

  const { data, isFetching, isError, error } = useQuery({
    queryKey: ["lookup", query, year],
    queryFn: () => lookup(query as string, year),
    enabled: !!query,
  });

  const hasSearched = query !== null;

  return (
    <main className="relative min-h-screen">
      <div className="grid-bg pointer-events-none absolute inset-0 opacity-40" />

      <div className="relative mx-auto flex max-w-3xl flex-col px-4 py-10 sm:py-16">
        {/* Hero */}
        <header className="mb-8 text-center">
          <div className="mb-4 inline-flex items-center gap-2 rounded border border-zinc-800 bg-zinc-900/60 px-3 py-1 font-mono text-xs font-medium text-zinc-400">
            <Terminal className="h-3.5 w-3.5 text-indigo-400" />
            CVE · CISA KEV · Lifecycle Intelligence
          </div>
          <h1 className="pb-1.5 text-4xl font-light leading-[1.1] tracking-[-0.04em] text-zinc-100 sm:text-5xl">
            KEVlar
          </h1>
          <p className="mx-auto mt-3 max-w-xl text-sm leading-relaxed text-zinc-400 sm:text-base">
            Armor woven from exploitation intelligence. Query by CVE ID, branded
            name, or product version — with bidirectional alias resolution, live
            CISA KEV status, end-of-life checks, and report-ready copy formats.
          </p>
        </header>

        {/* Search */}
        <SearchBar
          onSearch={setQuery}
          isLoading={isFetching}
          initialValue={query ?? ""}
        />

        {/* Year filter */}
        <div className="mt-3 flex items-center justify-center gap-2 text-xs text-zinc-500">
          <label htmlFor="year-filter" className="flex items-center gap-1.5">
            <CalendarRange className="h-3.5 w-3.5 text-zinc-600" />
            Filter by year
          </label>
          <select
            id="year-filter"
            value={year}
            onChange={(e) => setYear(e.target.value)}
            className="rounded-md border border-zinc-800 bg-zinc-900/80 px-2 py-1 font-mono text-xs text-zinc-300 outline-none transition hover:border-zinc-700 focus:border-indigo-500/60"
          >
            <option value="">All years</option>
            {YEAR_OPTIONS.map((y) => (
              <option key={y} value={y}>
                {y}
              </option>
            ))}
          </select>
          {year && (
            <button
              type="button"
              onClick={() => setYear("")}
              className="text-zinc-600 underline-offset-2 transition hover:text-zinc-400 hover:underline"
            >
              clear
            </button>
          )}
        </div>

        {/* Results region */}
        <section className="mt-10 flex flex-col gap-4" aria-live="polite">
          {isFetching && <SkeletonCard />}

          {!isFetching && isError && (
            <ErrorState message={(error as Error)?.message} />
          )}

          {!isFetching && !isError && data && (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-zinc-500">
                <span>
                  {RESOLVED_LABEL[data.resolvedVia]} ·{" "}
                  {data.results.length} result
                  {data.results.length === 1 ? "" : "s"}
                  {year && (
                    <span className="text-indigo-400"> · {year} only</span>
                  )}
                </span>
                {data.interpretation && (
                  <span className="font-mono text-zinc-400">
                    {data.interpretation.product}{" "}
                    <span className="text-indigo-400">
                      {data.interpretation.version}
                    </span>
                  </span>
                )}
              </div>

              {data.eol && <EolBanner eol={data.eol} />}

              {data.warning && (
                <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
                  <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
                  <span>{data.warning}</span>
                </div>
              )}

              {data.results.map((vuln) => (
                <VulnCard key={vuln.cveId} vuln={vuln} />
              ))}
            </>
          )}

          {!hasSearched && !isFetching && <EmptyHint />}
        </section>

        <footer className="mt-16 border-t border-zinc-800/60 pt-6 text-center text-xs text-zinc-600">
          Data sourced live from{" "}
          <a
            href="https://nvd.nist.gov/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-zinc-500 hover:text-zinc-300"
          >
            NIST NVD API 2.0
          </a>{" "}
          and the{" "}
          <a
            href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            target="_blank"
            rel="noopener noreferrer"
            className="text-zinc-500 hover:text-zinc-300"
          >
            CISA KEV Catalog
          </a>
          . For security research & reporting.
        </footer>
      </div>
    </main>
  );
}

function ErrorState({ message }: { message?: string }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-950/20 px-5 py-4 text-sm text-rose-200">
      <SearchX className="mt-0.5 h-5 w-5 flex-shrink-0 text-rose-400" />
      <div>
        <p className="font-semibold text-rose-300">No result</p>
        <p className="mt-1 leading-relaxed text-rose-200/90">
          {message || "Something went wrong. Try a different query."}
        </p>
      </div>
    </div>
  );
}

function EmptyHint() {
  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-zinc-800 bg-zinc-900/30 px-6 py-12 text-center">
      <ShieldCheck className="h-8 w-8 text-zinc-700" />
      <p className="max-w-sm text-sm text-zinc-500">
        Enter a CVE ID, a branded name, a product version (e.g.{" "}
        <span className="font-mono text-zinc-400">php 8.0.30</span>), or a
        keyword above to begin. Results show CVSS severity, CISA KEV
        exploitation status, end-of-life / outdated-version checks, and
        copy-ready reference formats.
      </p>
    </div>
  );
}
