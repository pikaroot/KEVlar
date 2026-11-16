import {
  AffectedProduct,
  CvssMetric,
  CvssSeverity,
  KevMetadata,
  VulnerabilityRecord,
} from "@/types/vulnerability";
import { brandedNameForCve } from "@/lib/alias-dictionary";

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_DETAIL = "https://nvd.nist.gov/vuln/detail";
const KEV_FEED =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/** Default timeout for external fetches (ms). */
const FETCH_TIMEOUT = 12_000;

// ---------------------------------------------------------------------------
// Minimal structural types for the external payloads we consume.
// ---------------------------------------------------------------------------

interface NvdCvssData {
  version?: string;
  baseScore?: number;
  baseSeverity?: string;
  vectorString?: string;
}

interface NvdCvssMetric {
  cvssData?: NvdCvssData;
  baseSeverity?: string;
}

interface NvdCve {
  id: string;
  published: string;
  lastModified: string;
  descriptions?: Array<{ lang: string; value: string }>;
  metrics?: {
    cvssMetricV40?: NvdCvssMetric[];
    cvssMetricV31?: NvdCvssMetric[];
    cvssMetricV30?: NvdCvssMetric[];
    cvssMetricV2?: NvdCvssMetric[];
  };
  weaknesses?: Array<{
    description?: Array<{ lang: string; value: string }>;
  }>;
  references?: Array<{ url: string; source?: string }>;
  // Structured "Affected Products" data (CNA-provided, source-grouped).
  affected?: Array<{
    affectedData?: Array<{
      vendor?: string;
      product?: string;
      defaultStatus?: string;
      cpes?: string[];
      versions?: Array<{
        version?: string;
        lessThan?: string;
        lessThanOrEqual?: string;
        status?: string;
        versionType?: string;
      }>;
    }>;
  }>;
  // Legacy CPE configuration tree (used when `affected` is absent).
  configurations?: Array<{
    nodes?: Array<{
      cpeMatch?: Array<{
        vulnerable?: boolean;
        criteria?: string;
        versionStartIncluding?: string;
        versionStartExcluding?: string;
        versionEndIncluding?: string;
        versionEndExcluding?: string;
      }>;
    }>;
  }>;
}

interface NvdResponse {
  vulnerabilities?: Array<{ cve: NvdCve }>;
  totalResults?: number;
}

interface KevCatalog {
  vulnerabilities?: Array<{
    cveID: string;
    vulnerabilityName?: string;
    dateAdded?: string;
    dueDate?: string;
    requiredAction?: string;
    knownRansomwareCampaignUse?: string;
    notes?: string;
  }>;
}

// ---------------------------------------------------------------------------
// Fetch helpers
// ---------------------------------------------------------------------------

async function fetchJson<T>(
  url: string,
  init: RequestInit & { next?: { revalidate?: number } } = {}
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
  try {
    // NVD grants much higher rate limits with an API key. Supply one via the
    // NVD_API_KEY environment variable to avoid 403/429 throttling.
    const apiKey = url.startsWith(NVD_BASE) ? process.env.NVD_API_KEY : undefined;
    const res = await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "User-Agent": "KEVlar/1.0 (security-research-utility)",
        ...(apiKey ? { apiKey } : {}),
        ...(init.headers || {}),
      },
    });
    if (!res.ok) {
      throw new Error(`Upstream responded ${res.status} ${res.statusText}`);
    }
    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// CISA KEV catalog — cached in module memory with periodic revalidation.
// ---------------------------------------------------------------------------

type KevIndex = Map<string, KevMetadata>;

let kevCache: { index: KevIndex; fetchedAt: number } | null = null;
const KEV_TTL = 60 * 60 * 1000; // 1 hour

function buildKevIndex(catalog: KevCatalog): KevIndex {
  const index: KevIndex = new Map();
  for (const entry of catalog.vulnerabilities ?? []) {
    if (!entry.cveID) continue;
    const ransom = entry.knownRansomwareCampaignUse;
    index.set(entry.cveID.toUpperCase(), {
      isKev: true,
      dateAdded: entry.dateAdded,
      dueDate: entry.dueDate,
      requiredAction: entry.requiredAction,
      knownRansomwareCampaignUse:
        ransom === "Known" ? "Known" : ransom === "Unknown" ? "Unknown" : undefined,
      notes: entry.notes,
    });
  }
  return index;
}

/**
 * Returns the KEV index, refreshing it at most once per TTL. On fetch failure
 * it serves any stale cache; if there is no cache at all it returns null so the
 * caller can degrade gracefully (KEV status reported as "unknown").
 */
export async function getKevIndex(): Promise<KevIndex | null> {
  const now = Date.now();
  if (kevCache && now - kevCache.fetchedAt < KEV_TTL) {
    return kevCache.index;
  }
  try {
    const catalog = await fetchJson<KevCatalog>(KEV_FEED, {
      next: { revalidate: 3600 },
    });
    const index = buildKevIndex(catalog);
    kevCache = { index, fetchedAt: now };
    return index;
  } catch {
    // Serve stale data if we have it; otherwise signal degraded mode.
    if (kevCache) return kevCache.index;
    return null;
  }
}

// ---------------------------------------------------------------------------
// NVD mapping
// ---------------------------------------------------------------------------

function pickDescription(cve: NvdCve): string {
  const en = cve.descriptions?.find((d) => d.lang === "en");
  return (en?.value || cve.descriptions?.[0]?.value || "No description available.").trim();
}

function normalizeSeverity(raw?: string, score?: number): CvssSeverity {
  const s = (raw || "").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH" || s === "MEDIUM" || s === "LOW") {
    return s as CvssSeverity;
  }
  // Derive from score when severity string is absent (common for CVSS v2).
  if (typeof score === "number" && score > 0) {
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    return "LOW";
  }
  return "UNKNOWN";
}

/** Priority used to pick the primary metric: newest CVSS version wins. */
const VERSION_PRIORITY: Record<CvssMetric["version"], number> = {
  "4.0": 4,
  "3.1": 3,
  "3.0": 2,
  "2.0": 1,
};

function toMetric(
  version: CvssMetric["version"],
  m: NvdCvssMetric | undefined
): CvssMetric | null {
  const data = m?.cvssData;
  if (!data) return null;
  const score = data.baseScore ?? 0;
  return {
    version,
    score,
    severity: normalizeSeverity(data.baseSeverity ?? m?.baseSeverity, score),
    vectorString: data.vectorString ?? "",
  };
}

/**
 * Collect every CVSS version present on the CVE (4.0 → 2.0) and pick the
 * highest-version one as the primary metric shown on the card.
 */
function pickCvssMetrics(cve: NvdCve): VulnerabilityRecord["cvssMetrics"] {
  const metrics = cve.metrics;
  const all: CvssMetric[] = [];

  const v40 = toMetric("4.0", metrics?.cvssMetricV40?.[0]);
  const v31 = toMetric("3.1", metrics?.cvssMetricV31?.[0]);
  const v30 = toMetric("3.0", metrics?.cvssMetricV30?.[0]);
  const v2 = toMetric("2.0", metrics?.cvssMetricV2?.[0]);

  for (const m of [v40, v31, v30, v2]) {
    if (m) all.push(m);
  }

  // Sort by version priority (newest first) for both display and primary pick.
  all.sort((a, b) => VERSION_PRIORITY[b.version] - VERSION_PRIORITY[a.version]);

  const primary: CvssMetric =
    all[0] ?? {
      version: "3.1",
      score: 0,
      severity: "UNKNOWN",
      vectorString: "",
    };

  return { primary, all };
}

function pickWeaknesses(cve: NvdCve): string[] {
  const out = new Set<string>();
  for (const w of cve.weaknesses ?? []) {
    for (const d of w.description ?? []) {
      if (d.lang === "en" && /^CWE-\d+$/i.test(d.value)) {
        out.add(d.value.toUpperCase());
      }
    }
  }
  return [...out];
}

function pickReferences(cve: NvdCve): VulnerabilityRecord["references"] {
  const refs = cve.references ?? [];
  return refs.slice(0, 8).map((r) => {
    let source = r.source || "";
    if (!source) {
      try {
        source = new URL(r.url).hostname.replace(/^www\./, "");
      } catch {
        source = "reference";
      }
    }
    return { url: r.url, source };
  });
}

/**
 * Normalize NVD's structured affected-version data. Prefers the CNA-provided
 * `affected` block; falls back to the legacy CPE `configurations` tree. Both
 * are far more precise than the prose description — many CVEs (e.g.
 * CVE-2024-4741 for OpenSSL 3.2.1) only record the affected version here.
 */
function pickAffected(cve: NvdCve): AffectedProduct[] {
  const out: AffectedProduct[] = [];

  for (const grp of cve.affected ?? []) {
    for (const ad of grp.affectedData ?? []) {
      if (!ad.versions || ad.versions.length === 0) continue;
      out.push({
        vendor: ad.vendor,
        product: ad.product,
        cpes: ad.cpes,
        defaultStatus: ad.defaultStatus,
        versions: ad.versions.map((v) => ({
          version: v.version,
          lessThan: v.lessThan,
          lessThanOrEqual: v.lessThanOrEqual,
          status: v.status,
        })),
      });
    }
  }
  if (out.length > 0) return out;

  // Legacy CPE configuration tree.
  for (const cfg of cve.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const cm of node.cpeMatch ?? []) {
        if (cm.vulnerable === false || !cm.criteria) continue;
        const parts = cm.criteria.split(":"); // cpe:2.3:part:vendor:product:ver:…
        const cpeVersion = parts[5];
        const hasRange =
          cm.versionStartIncluding ||
          cm.versionStartExcluding ||
          cm.versionEndIncluding ||
          cm.versionEndExcluding;
        out.push({
          vendor: parts[3],
          product: parts[4],
          cpes: [cm.criteria],
          defaultStatus: "unaffected",
          versions: [
            {
              version:
                cm.versionStartIncluding ??
                (!hasRange && cpeVersion && /^\d/.test(cpeVersion)
                  ? cpeVersion
                  : undefined),
              greaterThan: cm.versionStartExcluding,
              lessThan: cm.versionEndExcluding,
              lessThanOrEqual: cm.versionEndIncluding,
              status: "affected",
            },
          ],
        });
      }
    }
  }
  return out;
}

function mapNvdCve(cve: NvdCve, kev: KevMetadata): VulnerabilityRecord {
  const cveId = cve.id.toUpperCase();
  return {
    cveId,
    nvdUrl: `${NVD_DETAIL}/${cveId}`,
    brandedName: brandedNameForCve(cveId),
    description: pickDescription(cve),
    publishedDate: cve.published,
    lastModifiedDate: cve.lastModified,
    cvssMetrics: pickCvssMetrics(cve),
    cisaKev: kev,
    references: pickReferences(cve),
    weaknesses: pickWeaknesses(cve),
    affected: pickAffected(cve),
  };
}

// ---------------------------------------------------------------------------
// Public lookup functions
// ---------------------------------------------------------------------------

async function correlateKev(cveId: string): Promise<KevMetadata> {
  const index = await getKevIndex();
  if (!index) return { isKev: false }; // degraded — treat as not-listed
  return index.get(cveId.toUpperCase()) ?? { isKev: false };
}

/** Fetch a single CVE by canonical ID and merge in KEV data. */
export async function fetchByCveId(
  cveId: string
): Promise<VulnerabilityRecord | null> {
  const url = `${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`;
  const data = await fetchJson<NvdResponse>(url, { next: { revalidate: 1800 } });
  const first = data.vulnerabilities?.[0]?.cve;
  if (!first) return null;
  const kev = await correlateKev(first.id);
  return mapNvdCve(first, kev);
}

/**
 * Fetch several CVE IDs concurrently (used when an alias maps to multiple CVEs).
 * IDs that NVD does not know about are silently skipped; results preserve the
 * input order. Throws only if every lookup errors (so callers can surface a
 * genuine upstream failure).
 */
export async function fetchByCveIds(
  cveIds: string[]
): Promise<VulnerabilityRecord[]> {
  const settled = await Promise.allSettled(
    cveIds.map((id) => fetchByCveId(id))
  );

  const records: VulnerabilityRecord[] = [];
  let errors = 0;
  settled.forEach((r) => {
    if (r.status === "fulfilled") {
      if (r.value) records.push(r.value);
    } else {
      errors += 1;
    }
  });

  // Only propagate an error if nothing at all could be fetched.
  if (records.length === 0 && errors > 0) {
    throw new Error("All concurrent NVD lookups failed");
  }
  return records;
}

/**
 * Keyword search against NVD; returns up to `limit` mapped records.
 *
 * NVD orders keyword results oldest-first, which is the wrong end for a
 * version query (CVEs affecting a currently-shipping release are recent). With
 * `recent: true` we read the total count, then page to the tail so the newest
 * `limit` CVEs are returned (newest first). That single extra count request is
 * cached, and the window is where in-range matches for a live version live.
 */
export async function fetchByKeyword(
  keyword: string,
  limit = 10,
  opts: { recent?: boolean } = {}
): Promise<VulnerabilityRecord[]> {
  const base = `${NVD_BASE}?keywordSearch=${encodeURIComponent(keyword)}`;
  let startIndex = 0;

  if (opts.recent) {
    const countUrl = `${base}&resultsPerPage=1`;
    const count = await fetchJson<NvdResponse>(countUrl, {
      next: { revalidate: 1800 },
    });
    const total = count.totalResults ?? 0;
    startIndex = Math.max(0, total - limit);
  }

  const url = `${base}&resultsPerPage=${limit}&startIndex=${startIndex}`;
  const data = await fetchJson<NvdResponse>(url, { next: { revalidate: 1800 } });
  const items = (data.vulnerabilities ?? []).slice(0, limit);
  if (opts.recent) items.reverse(); // newest first

  const records: VulnerabilityRecord[] = [];
  for (const item of items) {
    if (!item.cve) continue;
    const kev = await correlateKev(item.cve.id);
    records.push(mapNvdCve(item.cve, kev));
  }
  return records;
}

/**
 * Keyword search constrained to a single CVE publication year. NVD caps any
 * date range at 120 days, so the year is split into four quarter windows,
 * fetched in parallel and merged. Each window is keyword- and date-scoped, so
 * the result sets are small and fast. Returns records published in that year
 * (the caller still filters on the CVE-ID year).
 */
export async function fetchByKeywordInYear(
  keyword: string,
  year: string,
  perWindow = 200
): Promise<VulnerabilityRecord[]> {
  const base = `${NVD_BASE}?keywordSearch=${encodeURIComponent(keyword)}`;
  const quarters: Array<[string, string]> = [
    [`${year}-01-01T00:00:00.000`, `${year}-03-31T23:59:59.999`],
    [`${year}-04-01T00:00:00.000`, `${year}-06-30T23:59:59.999`],
    [`${year}-07-01T00:00:00.000`, `${year}-09-30T23:59:59.999`],
    [`${year}-10-01T00:00:00.000`, `${year}-12-31T23:59:59.999`],
  ];

  const pages = await Promise.all(
    quarters.map(([start, end]) => {
      const url = `${base}&pubStartDate=${encodeURIComponent(
        start
      )}&pubEndDate=${encodeURIComponent(end)}&resultsPerPage=${perWindow}`;
      return fetchJson<NvdResponse>(url, { next: { revalidate: 3600 } }).catch(
        () => null // tolerate a failed quarter rather than failing the search
      );
    })
  );

  const records: VulnerabilityRecord[] = [];
  const seen = new Set<string>();
  for (const page of pages) {
    for (const item of page?.vulnerabilities ?? []) {
      if (!item.cve) continue;
      const id = item.cve.id.toUpperCase();
      if (seen.has(id)) continue;
      seen.add(id);
      const kev = await correlateKev(item.cve.id);
      records.push(mapNvdCve(item.cve, kev));
    }
  }
  return records;
}

/** Whether the KEV data source is currently reachable (for warnings). */
export async function isKevAvailable(): Promise<boolean> {
  return (await getKevIndex()) !== null;
}
