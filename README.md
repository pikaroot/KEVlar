# KEVlar — CVE, CISA KEV & Lifecycle Intelligence

*Armor woven from exploitation intelligence.*

A lightweight, dark-mode security search utility for analysts, penetration testers,
and vulnerability managers. Query by standard identifier (`CVE-2024-4577`), by
community/branded name (`PHP2SHELL`, `Log4Shell`, `Heartbleed`, …), or by product
version (`php 8.0.30`, `jquery ui 1.11.1`) — with bidirectional alias resolution,
live CISA KEV exploitation status, end-of-life / outdated-version checks, and
one-click report-ready copy formats.

## Stack

- **Next.js 14** (App Router) with server-side API proxying
- **TypeScript** (strict)
- **Tailwind CSS** (dark, offensive-security aesthetic)
- **TanStack Query v5** for client caching, dedup, and loading skeletons
- **Lucide React** icons
- Data: **NIST NVD API 2.0** + **CISA KEV** catalog

## Getting started

> **Node version note (this machine):** the system `node` at `/usr/bin/node`
> (Kali's packaged 20.19.5) is broken — its bundled `undici` references
> `webidl.util.markAsUncloneable`, which the build omits, so `new Headers()` /
> `fetch` throw and both `next build` and runtime API calls fail. A working
> official Node 22 is installed at
> `/home/kali/.local/node/node-v22.11.0-linux-x64/bin`. Put it first on `PATH`:
>
> ```bash
> export PATH="/home/kali/.local/node/node-v22.11.0-linux-x64/bin:$PATH"
> node -v   # should print v22.11.0
> ```
>
> (Or install any Node ≥18.18 from nodejs.org / nvm — see `.nvmrc`.)

```bash
npm install
cp .env.example .env.local   # optional: add an NVD_API_KEY to avoid throttling
npm run dev                  # http://localhost:3000
```

Production:

```bash
npm run build && npm start
```

## Docker deployment

The app ships a multi-stage `Dockerfile` (Next.js **standalone** output → a slim
`node:22-alpine` image running as a non-root user) and a `docker-compose.yml`.

**Plain Docker:**

```bash
docker build -t kevlar .
docker run -d --name kevlar -p 3000:3000 \
  -e NVD_API_KEY=your-key-here \
  --restart unless-stopped kevlar
# → http://<server-ip>:3000
```

**Docker Compose (recommended for a home server / Dockge / Portainer):**

```bash
echo "NVD_API_KEY=your-key-here" > .env   # optional
docker compose up -d --build
```

In **Dockge** or **Portainer**, create a new stack, paste the contents of
`docker-compose.yml`, set `NVD_API_KEY` in the stack's environment, and deploy.
To use a prebuilt image instead of building on the box, push the image to a
registry and swap `build: .` for `image: <your-registry>/kevlar:latest` in the
compose file.

Notes:
- `NVD_API_KEY` is **optional** but recommended — it raises NVD's rate limits.
  It is passed at runtime and never baked into the image (see `.dockerignore`).
- Change the host port by editing the left side of `3000:3000` (e.g. `8080:3000`).
- The container exposes a `/` HTTP healthcheck, so orchestrators can detect readiness.
- Put a reverse proxy (Caddy / Nginx / Traefik) in front for TLS if exposing it
  beyond your LAN.

## Search UX

- **Type-ahead prediction** (`src/lib/suggestions.ts`) — an offline, zero-latency
  autocomplete that predicts branded/alias names (`Heartbleed` ⇒ `CVE-2014-0160`),
  ~90 common product names (`openssl`, `jquery ui`, …), and canonical CVE-ID
  shaping as you type. Prefix matches rank first; arrow keys + Enter/Tab select,
  Escape dismisses. Choosing a product fills `<product> ` and keeps focus so you
  can append a version.
- **Year filter** — a dropdown next to the search box restricts results to CVEs
  assigned in a given year (`/api/lookup?q=…&year=YYYY`). For keyword and version
  searches it queries NVD across that year in four quarter windows (the API caps
  any date range at 120 days) and keeps only CVEs whose ID year matches. Precise
  alias / CVE-ID lookups ignore the filter.

## How search resolves (`/api/lookup?q=…`)

1. **Alias / branded name** — checked against `src/lib/alias-dictionary.ts`
   (case-insensitive, whitespace-tolerant: `Dirty COW` ⇒ `CVE-2016-5195`). An
   alias may map to **multiple CVEs** (e.g. `ProxyLogon` ⇒ 4 CVEs,
   `PHP2SHELL` ⇒ 2); those are fetched concurrently and rendered as one card
   each.
2. **Direct CVE ID** — loose formats like `cve 2026 109618` or `2026-109618`
   are normalized to canonical `CVE-2026-109618`.
3. **Version-aware technology search** — a `<product> <version>` query (e.g.
   `php 8.0.30`, `openssl 3.2.1`, `jquery ui 1.11.1`) returns **only** CVEs that
   place the typed version inside an affected range for that product. Two
   sources are consulted, structured first. See `src/lib/version-search.ts`.
   - **Structured "Affected Products" (authoritative).** NVD's machine-readable
     version ranges — `cve.affected[].versions[]` (CNA data) or the legacy CPE
     `configurations` tree — are matched directly (`version ≤ v < lessThan`,
     etc.). This is exact and already product-scoped, and it catches cases the
     prose omits entirely: e.g. `openssl 3.2.1` is listed affected by
     `CVE-2024-4741` only here (`3.2.0 ≤ version < 3.2.2`), never in the
     description, which actually says the FIPS modules in 3.2 are *not* affected.
     Matched cards are tagged **NVD Affected Products**.
   - **Description fallback.** When a CVE carries no structured data for the
     product, the affected range is parsed from the prose, gated so the result
     is genuinely about that product:
     - *Branch-aware ranges.* `"before 8.0, 8.0 before 8.0.7, 9.0 before 9.0.4"`,
       `"8.1.x before 8.1.29"`, and `"from 11.0.0-M1 through 11.0.25"` are read
       per branch / with their lower bound, so `php 8.0.30` is not matched by an
       `8.1.x`/`9.0` ceiling and `openssl 3.2.2` is not matched by a FortiOS
       `through 11.0.25` range.
     - *Whole-phrase product match.* `jquery ui` must appear as a phrase
       (`jQuery-UI`, `jQuery.UI` included) — never a lone `jquery` token or a
       product that merely shares the number (`axios 1.11.1`).
     - *The product must own the clause.* A product named only as a dependency
       ("…**using jQuery UI**. Prior to 2.1.67…" — that range is elFinder's),
       only as an ecosystem library ("a **PHP** SDK"), only inside a vuln name
       ("…GOLDENDOODLE, **OpenSSL** 0-length… FortiOS … version 4.000 to 4.036"),
       or only in a far-off intro sentence is excluded.
   - Matched cards show the evidence (a CPE range or a description snippet) and
     its source. When nothing is confirmed, the app says so plainly instead of
     padding with keyword hits.
   - *Letter-aware version compare.* Comparisons order OpenSSL-style patch
     letters (`1.1.1 < 1.1.1a < 1.1.1y`) and keep SemVer pre-releases below
     their release (`11.0.0-M1 < 11.0.0`), so `openssl 1.1.1w` resolves correctly.
4. **Keyword search** — anything else runs an NVD `keywordSearch`.

> Version search prefers NVD's structured CPE / Affected-Products ranges and
> falls back to reasoning about the ranges each CVE writes in prose. It errs
> toward precision — a confirmed match (with its source) or an honest "no
> match" rather than guesses. Prose-only coverage still depends on NVD phrasing.

### End-of-life & outdated-version checks

Every version lookup also resolves the product's **release lifecycle** via the
free [endoflife.date](https://endoflife.date) API (`src/lib/eol-client.ts`,
cached in-memory) and shows a coloured banner above the results:

| Posture | Meaning |
| --- | --- |
| 🔴 **End-of-life** | The release branch no longer gets security fixes (e.g. `php 8.0.30` → EOL 2023-11-26). Upgrade recommended, with the latest supported release named. |
| 🟡 **Update available** | The branch is still supported but the typed version is behind the latest patch (e.g. `php 8.4.1` → update to `8.4.27`). |
| 🟢 **Supported** | Current branch, latest patch. |
| ⚪ **Lifecycle unknown** | Product not tracked by endoflife.date — the CVE results still render. |

Because this is independent of CVE matches, it surfaces risk even when a version
has **zero** matching CVEs — being on an unsupported release is itself the
finding. The product term is mapped to an endoflife.date slug via a small alias
table plus catalog matching, and the whole check is best-effort: any miss or
network error is silently skipped and never blocks the CVE lookup.

Each result is correlated against the CISA KEV catalog. If the KEV feed is
unreachable, the app degrades gracefully and surfaces a warning rather than
failing. When an alias covers several CVEs and some are missing from NVD, a
partial-result warning names the ones not found.

### Multi-version CVSS

NVD returns CVSS 4.0 / 3.1 / 3.0 / 2.0. To stay minimalist, each card shows only
the **highest available version** as the prominent badge (e.g. `9.2 CRITICAL ·
v4.0`); hovering or clicking it opens a popover (`cvss-popover.tsx`) listing
every version with its score, severity, and vector string. Every card also has a
**View on NVD** button linking to `https://nvd.nist.gov/vuln/detail/{CVE-ID}`.

## Copy formats

| Action | Output |
| --- | --- |
| **CVE ID** | `CVE-2024-4577` |
| **Reference** | `[CVE-2024-4577] (CVSS 9.8 - CRITICAL) - …` |
| **Named Reference** | `[CVE-2024-4577 / PHP2SHELL] (CVSS 9.8 - CRITICAL) - …` |
| **Markdown** | Structured block for tickets & advisories |

## Extending the alias dictionary

Add entries to `VULN_ALIASES` in `src/lib/alias-dictionary.ts`. Reverse lookup
(CVE ⇒ branded name) is automatic.

## Notes

- NVD rate-limits unauthenticated requests. Set `NVD_API_KEY` in `.env.local`
  for reliable, higher-volume lookups.
- All external fetches run server-side through the `/api/lookup` route (no CORS
  issues, API key never reaches the browser).
