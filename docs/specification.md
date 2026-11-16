# Software Requirements Specification (SRS)

## Project Name: KEVlar — CVE, CISA KEV & Lifecycle Intelligence

## 1. System Prompt Context for Claude

> **Instruction for Claude:**
>
> You are acting as a Senior Full-Stack Engineer and Security Architect. Your task is to build a responsive, production-ready web application for looking up CVE and CISA KEV data based on the requirements below. Ensure bidirectional name resolution, support for aliases that map to multiple CVEs (e.g., querying `PHP2SHELL` resolves to both `CVE-2026-109618` and `CVE-2026-109619`), version-aware technology search (e.g., querying `php 8.0.39` returns CVEs whose descriptions place that version in the affected range, such as "...prior to 8.0.41..."), multi-tier clipboard copy functionality, and resilient external API fallback handling.

## 2. Executive Summary & Objective

* **Purpose:** A lightweight, high-performance security search utility that enables analysts, penetration testers, and vulnerability managers to query vulnerabilities using either standard identifiers (`CVE-YYYY-NNNNN`) or popular community/branded names (`PHP2SHELL`, `Log4Shell`, `Heartbleed`, etc.).
* **Key Differentiator:**
  1. Natural alias-to-CVE and CVE-to-alias discovery.
  2. One-click standardized clipboard copying formatted for vulnerability reports and advisory notes.
  3. Live indicators showing if an issue is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.
  4. Minimalist presentation of dense metrics (CVSS 4.0, 3.1, 3.0, 2.0) and direct NVD source verification.

## 3. Recommended Architecture & Tech Stack

| Layer | Technology | Role & Configuration | 
| ----- | ----- | ----- | 
| **Framework** | Next.js 14+ (App Router) | Server-side API route proxying, fast edge rendering, and built-in caching. | 
| **Language** | TypeScript (Strict) | Strict typing across external NVD payloads, CISA catalogs, and UI state. | 
| **Styling** | Tailwind CSS | Fast dark-mode utility styling with an offensive-security aesthetic. | 
| **Icons & Primitives** | Lucide React + Radix UI / shadcn | Accessible tooltips, dialogs, badges, and copy triggers. | 
| **Data Fetching & Cache** | TanStack Query v5 | Client-side query caching, query deduplication, loading skeletons. | 
| **External APIs** | NIST NVD API 2.0 + CISA KEV JSON | Primary vulnerability data and active exploitation catalog. | 

## 4. Design System & Cyber Aesthetics

* **Theme:** Default Dark Mode (`zinc-950` / `slate-950` background, high contrast).
* **Severity Color Map:**
  * **Critical (CVSS 9.0 – 10.0):** `bg-red-500/10 text-red-400 border-red-500/30`
  * **High (CVSS 7.0 – 8.9):** `bg-orange-500/10 text-orange-400 border-orange-500/30`
  * **Medium (CVSS 4.0 – 6.9):** `bg-amber-500/10 text-amber-400 border-amber-500/30`
  * **Low (CVSS 0.1 – 3.9):** `bg-blue-500/10 text-blue-400 border-blue-500/30`
* **Status Badges:**
  * **CISA KEV (Exploited in the Wild):** Flashing or highlighted crimson badge (`bg-rose-600 text-white font-bold`).
  * **Named Vulnerability Chip:** High-visibility purple/indigo badge (`bg-purple-500/10 text-purple-300 border-purple-500/30`) showing the colloquial name (e.g., `PHP2SHELL`).
* **Fonts:** `Inter` for regular UI text; `JetBrains Mono` or `Fira Code` for CVE codes, CVSS vector strings, and copy payloads.

## 5. Core Functional Requirements

### 5.1. Search Bar & Query Parser
* Centered search bar with auto-focus.
* **Smart Input Resolution (evaluated in order):**
  1. **Direct CVE Match:** Accepts inputs like `CVE-2026-109618`, `cve 2026 109618`, `2026-109618` and normalizes them.
  2. **Alias / Branded Name Match:** Accepts queries such as `PHP2SHELL`, `Log4Shell`, etc. If an alias maps to multiple CVEs, the UI must display a list of all associated vulnerability cards.
  3. **Version-Aware Technology Search:** Accepts a product plus a specific version (e.g. `php 8.0.30`, `jquery ui 1.11.1`, `openssl 1.0.1`, `apache 2.4.49`). The query is split into a product term and a target version, and the search **returns only confirmed matches** — CVEs that both place the target version inside an affected range parsed from the description *and* are genuinely about that product. The query term is treated as an indivisible unit; it is never split so that an unrelated product sharing the version number (`axios 1.11.1`) or one word of the term (bare `jquery`) leaks in. Specifically:
     - **Branch-aware range parsing.** Multi-branch enumerations such as "before 8.0, 8.0 before 8.0.7, 9.0 before 9.0.4" and wildcard branches "8.1.x before 8.1.29" / "8.0.* before 8.0.30" are evaluated per release branch. A version in one branch is never flagged by another branch's ceiling (so `php 8.0.30` is **not** matched by a "9.0.4" or "8.1.x" clause), and a fixed version is not reported as vulnerable.
     - **Whole-phrase, subject-level product matching.** A multi-word product ("jquery ui") must appear as a contiguous phrase (hyphen/dot separators tolerated). A product that only appears as a dependency ("...using jQuery UI. Prior to 2.1.67..." where the range belongs to elFinder), as an ecosystem library ("a PHP SDK"), or in a distant intro sentence does **not** count — the product must govern the matched version clause. A genuine dependency-version constraint ("used with OpenSSL before 1.0.2") is kept.
     - When no CVE confirms the queried product+version, the resolver returns an explicit "no confirmed match" response rather than padding results with unrelated keyword hits. Matched cards display the affected-version evidence snippet.
  4. **Keyword / Description Search:** Fallbacks to NVD keyword search if no direct, alias, or version match applies.
* **End-of-Life / Outdated-Version Check:** On every version-aware lookup, the application also resolves the product's **release lifecycle** (via the endoflife.date API, `lib/eol-client.ts`) and surfaces a prominent, colour-coded indicator with an upgrade recommendation:
  - **End-of-life** (red): the queried version's release branch no longer receives security fixes (e.g. `php 8.0.30` → EOL 2023-11-26). The recommendation names the latest supported release.
  - **Update available** (amber): the branch is supported but the version is behind the latest patch (e.g. `php 8.4.1` → update to `8.4.27`).
  - **Supported** (green): current branch and latest patch.
  - **Unknown** (neutral): the product is not tracked upstream; CVE results still render.
  This check is independent of CVE matches — it must surface even when a version has zero matching CVEs (running an unsupported release is itself a finding) — and is best-effort: any resolution or network failure is silently skipped and never blocks the CVE lookup.

### 5.2. Data Resolution Pipeline (`/api/lookup`)
The backend route handler performs:
1. **Alias Lookup:** Checks `lib/alias-dictionary.ts`. Extracts the target CVE ID(s).
2. **NVD API Fetch:** Requests NIST NVD API 2.0. If multiple IDs are returned from the alias (like PHP2SHELL), fetch all concurrently.
3. **Version-Aware Ranking:** When the query is a `<product> <version>` pair, fetch a candidate set via NVD keyword search (newest-first, since in-range CVEs for a live release are recent) and filter it with `lib/version-search.ts`, which parses branch-aware affected-version constraints ("before", "prior to", "through", "A.B.x/A.B.* before A.B.Z", per-branch enumerations, ranges) from each description and keeps **only** CVEs whose range includes the queried version *and* whose description makes the queried product the governor of that clause (phrase match, subject check, dependency/ecosystem exclusion). If none qualify, return an explicit no-match response rather than unrelated keyword hits.
4. **CISA KEV Correlation:** Checks against the CISA catalog to append exploit metadata.
5. **Lifecycle Resolution:** For version queries, resolve the product against endoflife.date (`lib/eol-client.ts`) in parallel with the CVE fetch, map the version to its release branch, and attach an `eol` posture (end-of-life / outdated / supported / unknown) with a recommendation to the response. Best-effort and non-blocking.

### 5.3. UI Presentation Requirements (NVD Links & Multi-CVSS)
* **Official NVD Reference Link:** Every vulnerability card MUST have an explicit, minimalist "View on NVD" icon/button linking directly to `https://nvd.nist.gov/vuln/detail/{CVE-ID}`.
* **Minimalist CVSS Display:** The API returns CVSS 4.0, 3.1, 3.0, and 2.0. To avoid ruining the minimalistic design:
  * Display the *highest available version's score* as the primary prominent badge (e.g., `9.8 CRITICAL (v4.0)`).
  * Make the primary badge interactive (a Radix UI Popover, Hover Card, or discreet dropdown) to reveal the other available scores (v3.1, v3.0, v2.0) and their vector strings gracefully when the user hovers or clicks.

### 5.4. One-Click Copy Actions
Every result card must provide copy triggers with immediate visual feedback:
1. **Primary Reference Copy (Single-line report format):**
   * *Example:* `[CVE-2026-109618] (CVSS 9.8 - CRITICAL) - [Description]`
2. **Named Reference Copy (If an alias exists):**
   * *Example:* `[CVE-2026-109618 / PHP2SHELL] (CVSS 9.8 - CRITICAL) - [Description]`
3. **Quick CVE ID Copy:** Copies only the identifier string (e.g., `CVE-2026-109618`).
4. **Markdown Export Copy:** Copies a structured Markdown block.

## 6. TypeScript Data Models

```typescript
export type CvssSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface CvssMetric {
  version: '4.0' | '3.1' | '3.0' | '2.0';
  score: number;
  severity: CvssSeverity;
  vectorString: string;
}

export interface KevMetadata {
  isKev: boolean;
  dateAdded?: string;
  dueDate?: string;
  requiredAction?: string;
  knownRansomwareCampaignUse?: 'Known' | 'Unknown';
  notes?: string;
}

export interface VulnerabilityRecord {
  cveId: string;
  nvdUrl: string; // Must format as https://nvd.nist.gov/vuln/detail/{cveId}
  brandedName?: string | null; 
  title?: string;
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  cvssMetrics: {
    primary: CvssMetric; // The highest available version to show on the main UI
    all: CvssMetric[];   // Array of all available versions (4.0, 3.1, 3.0, 2.0) for the popover
  };
  cisaKev: KevMetadata;
  references: Array<{
    url: string;
    source: string;
  }>;
  weaknesses: string[]; 
}

export interface AliasMapping {
  displayName: string;
  cveIds: string[]; // Array to support aliases covering multiple CVEs
  tags?: string[];
}
```

## 7. Known Alias Dictionary (`lib/alias-dictionary.ts`)

Claude must initialize this map and provide an extensible structure, ensuring these are verified, industry-recognized branded names:

```typescript
export const VULN_ALIASES: Record<string, AliasMapping> = {
  'php2shell': { cveIds: ['CVE-2026-109618', 'CVE-2026-109619'], displayName: 'PHP2SHELL' },
  'log4shell': { cveIds: ['CVE-2021-44228'], displayName: 'Log4Shell' },
  'heartbleed': { cveIds: ['CVE-2014-0160'], displayName: 'Heartbleed' },
  'eternalblue': { cveIds: ['CVE-2017-0144'], displayName: 'EternalBlue' },
  'proxylogon': { cveIds: ['CVE-2021-26855', 'CVE-2021-26857', 'CVE-2021-26858', 'CVE-2021-27065'], displayName: 'ProxyLogon' },
  'proxyshell': { cveIds: ['CVE-2021-34473', 'CVE-2021-34523', 'CVE-2021-31207'], displayName: 'ProxyShell' },
  'zerologon': { cveIds: ['CVE-2020-1472'], displayName: 'ZeroLogon' },
  'spring4shell': { cveIds: ['CVE-2022-22965'], displayName: 'Spring4Shell' },
  'dirtycow': { cveIds: ['CVE-2016-5195'], displayName: 'Dirty COW' },
  'pwnkit': { cveIds: ['CVE-2021-4034'], displayName: 'PwnKit' },
  'bluekeep': { cveIds: ['CVE-2019-0708'], displayName: 'BlueKeep' },
  'regresshion': { cveIds: ['CVE-2024-6387'], displayName: 'regreSSHion' },
  'poodle': { cveIds: ['CVE-2014-3566'], displayName: 'POODLE' },
};
```

## 8. Clipboard Formatter Utilities (`lib/formatters.ts`)

```typescript
import { VulnerabilityRecord } from '@/types/vulnerability';

/**
 * Produces standard single-line copy reference:
 * [CVE-ID] (CVSS X.X - SEVERITY) - Description
 */
export function formatQuickCopy(vuln: VulnerabilityRecord): string {
  const namePart = vuln.brandedName ? ` / ${vuln.brandedName}` : '';
  const score = vuln.cvssMetrics.primary.score > 0 ? vuln.cvssMetrics.primary.score.toFixed(1) : 'N/A';
  const severity = vuln.cvssMetrics.primary.severity;
  return `[${vuln.cveId}${namePart}] (CVSS ${score} - ${severity}) - ${vuln.description}`;
}

/**
 * Produces a full Markdown block for security reports
 */
export function formatMarkdownReport(vuln: VulnerabilityRecord): string {
  const cvssList = vuln.cvssMetrics.all
    .map(m => `    - **v${m.version}:** ${m.score.toFixed(1)} (${m.severity}) - \`${m.vectorString}\``)
    .join('\n');

  return [
    `### [${vuln.cveId}](${vuln.nvdUrl})${vuln.brandedName ? ` (${vuln.brandedName})` : ''}`,
    `- **Primary Severity:** CVSS ${vuln.cvssMetrics.primary.score.toFixed(1)} (${vuln.cvssMetrics.primary.severity})`,
    `- **All CVSS Metrics:**\n${cvssList}`,
    `- **In CISA KEV:** ${vuln.cisaKev.isKev ? 'YES (Active Exploitation)' : 'No'}`,
    `- **Description:** ${vuln.description}`,
    `- **Published:** ${vuln.publishedDate}`,
    `- **Official Source:** [NVD Reference](${vuln.nvdUrl})`,
    `- **References:**`,
    ...vuln.references.slice(0, 3).map(r => `  - [${r.source}](${r.url})`),
  ].join('\n');
}
```

## 9. Recommended File Structure

```text
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   └── lookup/
│   │   │       └── route.ts          # Normalizer, multi-CVE fetcher, NVD & KEV merger
│   │   ├── layout.tsx
│   │   └── page.tsx                  # Search Hero, chip suggestions, result cards
│   ├── components/
│   │   ├── search-bar.tsx            # Debounced search bar with alias suggestions
│   │   ├── vuln-card.tsx             # Card with primary severity & NVD link
│   │   ├── cvss-popover.tsx          # Minimalist hover card showing v4.0 -> v2.0
│   │   ├── eol-banner.tsx            # End-of-life / outdated-version indicator
│   │   ├── copy-button.tsx           # Multi-action clipboard button + toast
│   │   ├── kev-badge.tsx             # CISA KEV exploit banner
│   │   └── ui/                       # Button, Badge, Tooltip, HoverCard, Toast
│   ├── lib/
│   │   ├── alias-dictionary.ts       # Known alias array mappings
│   │   ├── formatters.ts             # Clipboard string formatting
│   │   ├── version-search.ts         # Parse "<product> <version>" + rank by affected range
│   │   ├── eol-client.ts             # endoflife.date lifecycle resolver (EOL / outdated)
│   │   └── nvd-client.ts             # Remote API fetcher with fallbacks
│   └── types/
│       └── vulnerability.ts          # Core TypeScript contracts
```

## 10. Execution Checklist for Claude

1. **TypeScript Definitions:** Setup `types/vulnerability.ts` emphasizing the multi-CVSS structure and `nvdUrl`.
2. **Alias Map:** Implement `lib/alias-dictionary.ts` noting that `cveIds` is now an array (and includes `POODLE` → `CVE-2014-3566`).
3. **Backend Route:** Build `app/api/lookup/route.ts` to handle returning multiple CVEs if an alias covers multiple IDs.
4. **Version-Aware Search:** Implement `lib/version-search.ts` to parse `<product> <version>` queries and rank candidate CVEs by whether the version falls within the affected range described in each CVE's description. Surface the matched evidence snippet on each card.
5. **UI Details:** Implement `cvss-popover.tsx` to handle the graceful display of CVSS 4.0, 3.1, 3.0, and 2.0 without clutter. Ensure every card has the NVD link icon.
6. **Lifecycle Check:** Implement `lib/eol-client.ts` (endoflife.date resolver, cached, best-effort) and `eol-banner.tsx` to show the end-of-life / outdated / supported posture and upgrade recommendation for version queries, independent of CVE matches.
6. **Copy Utilities:** Implement `lib/formatters.ts` exactly as specified to ensure rich markdown exports.