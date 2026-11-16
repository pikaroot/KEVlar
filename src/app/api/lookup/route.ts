import { NextRequest, NextResponse } from "next/server";
import { resolveAlias } from "@/lib/alias-dictionary";
import { normalizeCveId } from "@/lib/query-parser";
import {
  parseVersionQuery,
  rankByVersionRelevance,
  majorMinor,
} from "@/lib/version-search";
import {
  fetchByCveId,
  fetchByCveIds,
  fetchByKeyword,
  fetchByKeywordInYear,
  isKevAvailable,
} from "@/lib/nvd-client";
import { fetchEolStatus } from "@/lib/eol-client";
import { LookupResponse, VulnerabilityRecord } from "@/types/vulnerability";

export const runtime = "nodejs";
// Allow Next.js to cache identical lookups at the route level.
export const revalidate = 1800;

function bad(status: number, error: string) {
  return NextResponse.json({ error }, { status });
}

/** The assignment year encoded in a CVE id (CVE-YYYY-NNNN → "YYYY"). */
function cveYear(cveId: string): string | null {
  const m = cveId.match(/^CVE-(\d{4})-/i);
  return m ? m[1] : null;
}

export async function GET(req: NextRequest) {
  const raw = req.nextUrl.searchParams.get("q")?.trim() ?? "";
  if (!raw) {
    return bad(400, "Missing query parameter 'q'.");
  }
  if (raw.length > 120) {
    return bad(400, "Query too long.");
  }

  // Optional year filter (CVE assignment year). Applied to keyword and
  // version searches; precise alias/CVE-ID lookups ignore it.
  const yearParam = req.nextUrl.searchParams.get("year")?.trim() ?? "";
  const year = /^\d{4}$/.test(yearParam) ? yearParam : "";
  const byYear = (records: VulnerabilityRecord[]) =>
    year ? records.filter((r) => cveYear(r.cveId) === year) : records;

  // Data-source warning (KEV catalog unreachable → degraded correlation).
  const kevUp = await isKevAvailable();
  const warning = kevUp
    ? undefined
    : "CISA KEV catalog is currently unreachable; exploitation status may be incomplete.";

  try {
    // 1) Alias / branded-name resolution (may map to multiple CVEs).
    const alias = resolveAlias(raw);
    if (alias) {
      const records = await fetchByCveIds(alias.cveIds);
      if (records.length === 0) {
        return bad(
          404,
          `Alias "${alias.displayName}" maps to ${alias.cveIds.join(
            ", "
          )}, but no matching NVD record was found.`
        );
      }
      // Ensure the branded name is populated even if reverse lookup missed it.
      for (const record of records) {
        record.brandedName = record.brandedName ?? alias.displayName;
      }
      // Surface a partial-result note when some of the alias's CVEs were missing.
      let aliasWarning = warning;
      if (records.length < alias.cveIds.length) {
        const found = new Set(records.map((r) => r.cveId.toUpperCase()));
        const missing = alias.cveIds.filter(
          (id) => !found.has(id.toUpperCase())
        );
        const note = `${missing.length} of ${alias.cveIds.length} CVEs for "${alias.displayName}" were not found in NVD (${missing.join(", ")}).`;
        aliasWarning = warning ? `${warning} ${note}` : note;
      }
      const body: LookupResponse = {
        query: raw,
        resolvedVia: "alias",
        results: records,
        warning: aliasWarning,
      };
      return NextResponse.json(body);
    }

    // 2) Direct CVE identifier.
    const cveId = normalizeCveId(raw);
    if (cveId) {
      const record = await fetchByCveId(cveId);
      if (!record) {
        return bad(404, `No NVD record found for ${cveId}.`);
      }
      const body: LookupResponse = {
        query: raw,
        resolvedVia: "cve-id",
        results: [record],
        warning,
      };
      return NextResponse.json(body);
    }

    // 3) Version-aware technology search (e.g. "php 8.0.39").
    const versionQuery = parseVersionQuery(raw);
    if (versionQuery) {
      const { product, version } = versionQuery;

      // Candidate pull: the newest CVEs for "<product> <major.minor>" (in-range
      // CVEs for a live release are recent, and NVD orders keyword results
      // oldest-first). Broaden to the bare product term only if the focused
      // slice yields no confirmed match.
      const branch = majorMinor(version);
      // Release-lifecycle lookup runs in parallel with the CVE search; it is
      // best-effort and never blocks or fails the response.
      const eolPromise = fetchEolStatus(product, version).catch(() => null);

      // With a year filter, pull year-scoped candidates directly (the recent
      // window would miss an older year). Otherwise use the newest CVEs for the
      // branch, broadening to the bare product only if nothing is confirmed.
      let candidates: VulnerabilityRecord[];
      let matched: VulnerabilityRecord[];
      if (year) {
        candidates = await fetchByKeywordInYear(product, year);
        matched = rankByVersionRelevance(candidates, version, product).filter(
          (r) => r.relevance?.matchedVersion
        );
      } else {
        candidates = await fetchByKeyword(`${product} ${branch}`, 60, {
          recent: true,
        });
        matched = rankByVersionRelevance(candidates, version, product).filter(
          (r) => r.relevance?.matchedVersion
        );
        if (matched.length === 0) {
          const broad = await fetchByKeyword(product, 60, { recent: true });
          const seen = new Set(candidates.map((c) => c.cveId));
          candidates = candidates.concat(
            broad.filter((b) => !seen.has(b.cveId))
          );
          matched = rankByVersionRelevance(candidates, version, product).filter(
            (r) => r.relevance?.matchedVersion
          );
        }
      }

      const eol = (await eolPromise) ?? undefined;
      const matchedInYear = byYear(matched);

      // Only confirmed matches are returned: a result must be the right product
      // AND have the queried version inside its affected range. We never pad
      // with unrelated keyword hits — that is what produced false "vulnerable"
      // results for versions and products the query never named.
      if (matchedInYear.length === 0) {
        const note =
          year && matched.length > 0
            ? `${matched.length} CVE(s) list ${product} ${version} as affected, but none were assigned in ${year}.`
            : `No CVE in NVD's data lists ${product} ${version} as affected. It may be a fixed or unaffected version, or the relevant advisories phrase their affected ranges in a form this tool can't parse. Try the product name alone for a full keyword search.`;
        const body: LookupResponse = {
          query: raw,
          resolvedVia: "version",
          results: [],
          interpretation: { product, version },
          eol,
          warning: warning ? `${warning} ${note}` : note,
        };
        return NextResponse.json(body);
      }

      const body: LookupResponse = {
        query: raw,
        resolvedVia: "version",
        results: matchedInYear.slice(0, 10),
        interpretation: { product, version },
        eol,
        warning,
      };
      return NextResponse.json(body);
    }

    // 4) Keyword / description search. With a year filter we pull the keyword's
    // CVEs published across that year (four quarter windows) and keep those
    // whose ID year matches — newest first.
    const rawResults = year
      ? await fetchByKeywordInYear(raw, year)
      : await fetchByKeyword(raw, 10);
    const results = year
      ? byYear(rawResults)
          .sort((a, b) => b.cveId.localeCompare(a.cveId))
          .slice(0, 20)
      : rawResults;
    if (results.length === 0) {
      const suffix = year
        ? ` assigned in ${year} (try a different year, or widen the keyword).`
        : ".";
      return bad(404, `No vulnerabilities matched "${raw}"${suffix}`);
    }
    const body: LookupResponse = {
      query: raw,
      resolvedVia: "keyword",
      results,
      warning,
    };
    return NextResponse.json(body);
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Unexpected error during lookup.";
    // NVD throttling is common without an API key — surface a helpful hint.
    const hint = /429|403/.test(message)
      ? " The NVD API may be rate-limiting this request; set NVD_API_KEY to raise limits."
      : "";
    return bad(502, `Upstream lookup failed: ${message}.${hint}`);
  }
}
