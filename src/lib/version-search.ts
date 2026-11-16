import {
  AffectedProduct,
  AffectedVersion,
  VulnerabilityRecord,
} from "@/types/vulnerability";

/**
 * Version-aware technology search.
 *
 * Turns a query like "php 8.0.30" or "jquery ui 1.11.1" into a product term
 * ("php", "jquery ui") plus a target version, then ranks candidate CVEs by
 * whether that version falls inside the affected range described in each CVE's
 * own description text — AND whether the product actually governs that range,
 * so that a CVE for a different product that merely shares a version number
 * (e.g. "axios 1.11.1" for a "jquery ui 1.11.1" search) is not returned.
 */

// A dotted numeric version, optionally with a pre-release suffix.
const VERSION_TOKEN = /\b(\d+\.\d+(?:\.\d+){0,3}(?:[-.][a-z0-9]+)*)\b/i;
// Reusable sub-pattern (as a string) for a dotted version inside larger regexes.
const V = "(\\d+\\.\\d+(?:\\.\\d+){0,2})";
// Optional "version"/"versions" filler word, as it commonly appears in NVD
// descriptions ("prior to version 1.13.0").
const VER = "(?:versions?\\s+)?";
// Optional pre-release / milestone suffix on a version ("-M1", "-beta",
// ".RELEASE", "_p1"). A letter is required right after the separator so this
// never swallows the numeric token of a hyphenated range like "1.0-2.0".
const SFX = "(?:[-._][a-z][a-z0-9]*)*";

export interface ParsedVersionQuery {
  product: string;
  version: string;
}

/**
 * Parse a "<product> <version>" query. Returns null when there is no dotted
 * version token or no product term left once the version is removed (a bare
 * version like "8.0.39" is not a meaningful technology search).
 */
export function parseVersionQuery(raw: string): ParsedVersionQuery | null {
  const trimmed = raw.trim();
  const m = trimmed.match(VERSION_TOKEN);
  if (!m) return null;

  const version = m[1];
  const product = trimmed.replace(m[0], " ").replace(/\s+/g, " ").trim();
  if (product.length < 2) return null;

  return { product, version };
}

// ---------------------------------------------------------------------------
// Version comparison (letter-aware, dotted parts).
//
// Each dotted segment is split into its leading number and a trailing suffix.
// Suffixes order within the same number as:
//   pre-release ("-rc1", "-M1", "+build")  <  release ("")  <  patch letter
//   ("a" < "b" < … < "y")
// so OpenSSL-style patch letters sort correctly (1.1.1 < 1.1.1a < 1.1.1y) while
// SemVer pre-releases still sort below their release (11.0.0-M1 < 11.0.0).
// ---------------------------------------------------------------------------

function toParts(v: string): number[] {
  return v
    .split(".")
    .map((p) => parseInt(p.replace(/[^0-9].*$/, ""), 10))
    .map((n) => (Number.isFinite(n) ? n : 0));
}

/** The "major.minor" branch of a version ("8.0.39" → "8.0"). */
export function majorMinor(version: string): string {
  const p = toParts(version);
  return `${p[0] ?? 0}.${p[1] ?? 0}`;
}

interface VersionSegment {
  num: number;
  suffix: string;
}

function parseSegment(seg: string): VersionSegment {
  const m = seg.match(/^(\d*)(.*)$/);
  const digits = m?.[1] ?? "";
  return { num: digits === "" ? 0 : parseInt(digits, 10), suffix: (m?.[2] ?? "").toLowerCase() };
}

/** Tier used to order a segment's suffix relative to the plain release. */
function suffixTier(suffix: string): number {
  if (!suffix) return 1; // the release itself
  const c = suffix[0];
  if (c === "-" || c === "+") return 0; // pre-release / build metadata → earlier
  return 2; // patch letter(s), e.g. OpenSSL "y" → later
}

function compareSuffix(a: string, b: string): number {
  const ta = suffixTier(a);
  const tb = suffixTier(b);
  if (ta !== tb) return ta < tb ? -1 : 1;
  if (a === b) return 0;
  return a < b ? -1 : 1; // lexicographic within the same tier
}

/** Returns -1 if a < b, 0 if equal, 1 if a > b (component-wise, zero-padded). */
export function compareVersions(a: string, b: string): number {
  const sa = a.split(".");
  const sb = b.split(".");
  const n = Math.max(sa.length, sb.length);
  for (let i = 0; i < n; i++) {
    const pa = parseSegment(sa[i] ?? "0");
    const pb = parseSegment(sb[i] ?? "0");
    if (pa.num !== pb.num) return pa.num < pb.num ? -1 : 1;
    const c = compareSuffix(pa.suffix, pb.suffix);
    if (c !== 0) return c;
  }
  return 0;
}

/** True when `version` is in the same major.minor branch as `branch` ("8.0"). */
function sameBranch(version: string, branch: string): boolean {
  const bp = toParts(branch);
  const vp = toParts(version);
  return (vp[0] ?? 0) === (bp[0] ?? 0) && (vp[1] ?? 0) === (bp[1] ?? 0);
}

function snippet(desc: string, idx: number, len: number): string {
  const start = Math.max(0, idx - 28);
  const end = Math.min(desc.length, idx + len + 28);
  return (
    (start > 0 ? "…" : "") +
    desc.slice(start, end).trim() +
    (end < desc.length ? "…" : "")
  );
}

export interface DescriptionMatch {
  affected: boolean;
  evidence?: string;
  /** Index/length of the matched constraint phrase within the description. */
  matchIndex?: number;
  matchLength?: number;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// A "from <version>" lower bound sitting immediately before an upper-bound
// clause, as in "from 11.0.0-M1 through 11.0.25". The upper-bound-only checks
// consult this so they don't flag versions BELOW the range's floor (3.2.2 is
// not in "from 11.0.0-M1 through 11.0.25" even though 3.2.2 < 11.0.25).
const FROM_BOUND_RE = new RegExp(`\\bfrom\\s+${VER}v?${V}${SFX}\\s*$`, "i");
function precedingFromBound(lower: string, matchIndex: number): string | null {
  const pre = lower.slice(Math.max(0, matchIndex - 60), matchIndex);
  const m = pre.match(FROM_BOUND_RE);
  return m ? m[1] : null;
}

/**
 * Decide whether `version` is affected according to the version constraints
 * phrased in a CVE description.
 *
 * Branch-scoped enumeration takes precedence. Descriptions frequently list a
 * ceiling per release branch, e.g.
 *   "before 8.0, 8.0 before 8.0.7, 9.0 before 9.0.4, and 10.0 before 10.0.0"
 *   "8.1.x before 8.1.29"
 * When any "<branch>[.x] before <ceiling-in-same-branch>" clause is present,
 * the description is enumerating per branch, so a plain "before X.Y.Z" must NOT
 * be read globally (otherwise 8.0.30 would be wrongly flagged as affected by a
 * "before 9.0.4" clause). A version is then affected only if it sits in one of
 * the named branches and below that branch's ceiling — or under a bare
 * "before X.Y" branch floor.
 */
export function evaluateDescription(
  desc: string,
  version: string
): DescriptionMatch {
  const lower = desc.toLowerCase();

  // 1) Branch-scoped ceilings: "A.B[.x|.*] before/prior to A.B.Z" (Z in branch
  // A.B). Both the "8.1.x" and "8.0.*" wildcard spellings are recognised.
  const branchRe = new RegExp(
    `(?<![\\w.])(\\d+\\.\\d+)(?:\\.(?:x|\\*))?\\s+(?:before|prior to|up to but not including)\\s+${VER}v?${V}`,
    "g"
  );
  const branchClauses: Array<{
    branch: string;
    ceiling: string;
    index: number;
    length: number;
  }> = [];
  let bm: RegExpExecArray | null;
  while ((bm = branchRe.exec(lower)) !== null) {
    if (sameBranch(bm[2], bm[1])) {
      branchClauses.push({
        branch: bm[1],
        ceiling: bm[2],
        index: bm.index,
        length: bm[0].length,
      });
    }
  }

  if (branchClauses.length > 0) {
    for (const c of branchClauses) {
      if (sameBranch(version, c.branch) && compareVersions(version, c.ceiling) < 0) {
        return {
          affected: true,
          evidence: snippet(desc, c.index, c.length),
          matchIndex: c.index,
          matchLength: c.length,
        };
      }
    }
    // Bare "before X.Y" floor: whole release branches below X.Y are affected.
    const floorRe = new RegExp(
      `(?:before|prior to|earlier than|older than)\\s+${VER}v?(\\d+\\.\\d+)(?![.\\d])`,
      "g"
    );
    let fm: RegExpExecArray | null;
    while ((fm = floorRe.exec(lower)) !== null) {
      if (compareVersions(version, fm[1]) < 0) {
        return {
          affected: true,
          evidence: snippet(desc, fm.index, fm[0].length),
          matchIndex: fm.index,
          matchLength: fm[0].length,
        };
      }
    }
    // Branch constructs exist but the version is in no affected branch.
    return { affected: false };
  }

  // 2) General single-range constraints, most specific first.
  const checks: Array<{
    re: RegExp;
    test: (m: RegExpExecArray) => boolean;
  }> = [
    // from A before B  → A <= v < B  (A may carry a milestone suffix, e.g.
    // "from 10.1.0-M1 before 10.1.59")
    {
      re: new RegExp(
        `from\\s+${VER}v?${V}${SFX}\\s+(?:before|prior to|up to but not including)\\s+${VER}v?${V}${SFX}`,
        "g"
      ),
      test: (m) =>
        compareVersions(version, m[1]) >= 0 &&
        compareVersions(version, m[2]) < 0,
    },
    // between A and B  → A <= v <= B
    {
      re: new RegExp(`between\\s+${VER}v?${V}\\s+and\\s+v?${V}`, "g"),
      test: (m) =>
        compareVersions(version, m[1]) >= 0 &&
        compareVersions(version, m[2]) <= 0,
    },
    // A through/to/- B  → A <= v <= B  (A may carry a milestone suffix, e.g.
    // "11.0.0-M1 through 11.0.25")
    {
      re: new RegExp(
        `${V}${SFX}\\s*(?:through|thru|to|-|–|—)\\s*${V}${SFX}`,
        "g"
      ),
      test: (m) =>
        compareVersions(version, m[1]) >= 0 &&
        compareVersions(version, m[2]) <= 0,
    },
    // before / prior to / earlier than X  → v < X. If this is the upper end of
    // a "from A ..." range, honour the lower bound A so a version below A is not
    // flagged ("from 2.0 before 2.5" must not match 1.9).
    {
      re: new RegExp(
        `(?:before|prior to|earlier than|up to but not including|less than|older than)\\s+${VER}v?${V}`,
        "g"
      ),
      test: (m) => {
        const from = precedingFromBound(lower, m.index);
        if (from !== null && compareVersions(version, from) < 0) return false;
        return compareVersions(version, m[1]) < 0;
      },
    },
    // X and earlier / or prior  → v <= X
    {
      re: new RegExp(
        `${V}\\s+(?:and|or)\\s+(?:earlier|prior|older|below|before)`,
        "g"
      ),
      test: (m) => compareVersions(version, m[1]) <= 0,
    },
    // through / up to and including X  → v <= X. If this is the upper end of a
    // "from A ..." range, honour the lower bound A ("from 11.0.0-M1 through
    // 11.0.25" must not match 3.2.2, which sits below the range).
    {
      re: new RegExp(`(?:through|up to and including)\\s+${VER}v?${V}`, "g"),
      test: (m) => {
        const from = precedingFromBound(lower, m.index);
        if (from !== null && compareVersions(version, from) < 0) return false;
        return compareVersions(version, m[1]) <= 0;
      },
    },
  ];

  for (const c of checks) {
    c.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = c.re.exec(lower)) !== null) {
      if (c.test(m)) {
        return {
          affected: true,
          evidence: snippet(desc, m.index, m[0].length),
          matchIndex: m.index,
          matchLength: m[0].length,
        };
      }
    }
  }

  return { affected: false };
}

/**
 * Build a whole-phrase matcher for the product term. Multi-word products
 * ("jquery ui") must appear as a contiguous phrase (separators flexible so
 * "jQuery-UI" / "jQuery.UI" still match), never as individual tokens — this is
 * what keeps a "jquery ui" search from matching bare jQuery-core CVEs or an
 * unrelated product. File extensions (".php") and compound words
 * ("phpMyConferences") are excluded via the word boundaries.
 */
function buildProductMatcher(product?: string): RegExp | null {
  const words = (product ?? "")
    .toLowerCase()
    .trim()
    .split(/\s+/)
    .filter((w) => w.length >= 2)
    .map(escapeRegExp);
  if (words.length === 0) return null;
  // Flexible separators BETWEEN the query's own words ("jquery ui" ⇒ "jQuery-UI",
  // "jQuery.UI"), but the OUTER boundaries reject a hyphen-joined neighbour so a
  // bare product does not match a different hyphenated identifier that merely
  // ends/starts with it ("php" must not match "Auth0-PHP"; ".php" stays out too).
  const phrase = words.join("[\\s._/\\-]+");
  return new RegExp(`(?<![\\w.\\-])${phrase}(?![\\w\\-])`, "i");
}

// Nouns that mark the preceding term as a thing built FOR/IN a technology
// rather than the technology itself ("a PHP SDK", "a Python package").
const ECOSYSTEM_NOUN =
  "(?:sdk|library|libraries|package|packages|module|modules|plugin|plugins|" +
  "extension|extensions|binding|bindings|wrapper|wrappers|connector|connectors|" +
  "driver|drivers|gem|crate|bundle|integration|client)";

/**
 * True when the product term appears as a genuine subject somewhere in the
 * description — i.e. at least once NOT immediately followed by an ecosystem
 * noun. "Auth0-PHP is a PHP SDK ..." names every standalone "PHP" as
 * "PHP SDK", so PHP is not the subject; "In PHP versions ..." is. This keeps a
 * "php" search off libraries that merely target PHP.
 */
function productIsSubject(desc: string, matcher: RegExp): boolean {
  const g = new RegExp(matcher.source, "gi");
  const nounRe = new RegExp(`^\\s+${ECOSYSTEM_NOUN}\\b`, "i");
  let m: RegExpExecArray | null;
  while ((m = g.exec(desc)) !== null) {
    if (!nounRe.test(desc.slice(m.index + m[0].length))) return true;
    if (g.lastIndex === m.index) g.lastIndex++;
  }
  return false;
}

/**
 * The text that governs a version clause: the sentence the clause sits in plus
 * the sentence immediately before it. A product named only in a far-off intro
 * (e.g. "elFinder ... using jQuery UI. <vuln text>. before 2.1.x") does not
 * govern the clause, so a version match against the clause is not that
 * product's — this keeps a "jquery ui" search off products that merely bundle
 * it, while still accepting "jQuery-UI is the official library. Prior to X".
 */
function clauseGovernor(desc: string, matchIndex: number): string {
  const before = desc.slice(0, matchIndex);
  const bounds = [...before.matchAll(/[.!?]\s+/g)].map(
    (m) => (m.index ?? 0) + m[0].length
  );
  const prevStart = bounds.length >= 2 ? bounds[bounds.length - 2] : 0;
  return desc.slice(prevStart, matchIndex);
}

// A product named only behind one of these is a dependency, not the subject
// ("...written in JavaScript using jQuery UI. Prior to 2.1.68, ...").
const DEP_PREFIX =
  /(?:\busing|\bvia|\bbased\s+on|\bpowered\s+by|\bbuilt\s+(?:on|with|using)|\bon\s+top\s+of|\bbundles?|\bincludes?)\s+$/i;

/**
 * Whether the product governs the version clause: it is named in the clause's
 * own or the preceding sentence, in a position other than as a dependency of
 * some other project. A mention that only ever follows "using"/"based on"/etc.
 * does not govern — it is the technology the affected product is built with.
 */
function productGovernsClause(
  desc: string,
  matchIndex: number,
  matcher: RegExp
): boolean {
  const window = clauseGovernor(desc, matchIndex);
  const g = new RegExp(matcher.source, "gi");
  let m: RegExpExecArray | null;
  while ((m = g.exec(window)) !== null) {
    if (!DEP_PREFIX.test(window.slice(0, m.index))) return true;
    if (g.lastIndex === m.index) g.lastIndex++;
  }
  return false;
}

/**
 * Whether a DIFFERENT product owns the version clause — i.e. a product-shaped
 * identifier (camelCase / digit-bearing, like "elFinder" or "phpMyAdmin") sits
 * right after the clause as its subject, and it is not our product. This is the
 * "Prior to 2.1.67, elFinder contains ..." case: jQuery UI is only the tech it
 * is built with, so the 2.1.67 range is elFinder's, not a jQuery UI match.
 */
function clauseOwnerConflict(
  desc: string,
  afterIndex: number,
  matcher: RegExp
): boolean {
  const after = desc.slice(afterIndex, afterIndex + 60);
  const m = after.match(/^[\s,;:]+([A-Za-z][\w.-]*)/);
  if (!m) return false;
  const owner = m[1];
  const looksLikeProduct = /[a-z][A-Z]/.test(owner) || /\d/.test(owner);
  // Re-test the matcher over the trailing text so a multi-word product named
  // after its own clause ("before 1.13.0, jQuery UI does X") is not a conflict.
  return looksLikeProduct && !matcher.test(after);
}

// Words that are part of a version enumeration rather than the product that
// owns it — skipped when walking back to find the owner of a version list.
const ENUM_FILLER = new Set([
  "version", "versions", "v", "to", "through", "thru", "and", "or", "below",
  "above", "before", "after", "earlier", "later", "prior", "up", "including",
  "between", "from", "x", "all", "series", "branch", "branches", "release",
  "releases", "of",
]);

/**
 * Whether a DIFFERENT product owns the version enumeration the match sits in.
 * Walks back from the matched version through the preceding run of version
 * numbers, range connectors and filler words ("FortiOS IPS engine version
 * 5.000 to 5.006, 4.000 to 4.036") to the product phrase that introduces the
 * list. If that owner is a real word and is not our product, the versions
 * belong to something else — so a bare mention of our product elsewhere in the
 * sentence (e.g. "OpenSSL" inside the vuln name "OpenSSL 0-length") must not
 * count as a match. Returns false when the walk-back hits a clause/sentence
 * boundary with no concrete owner, leaving the other heuristics in charge.
 */
function enumerationOwnerConflict(
  desc: string,
  matchIndex: number,
  matcher: RegExp
): boolean {
  let pre = desc.slice(0, matchIndex);
  // Peel the version enumeration off the end: punctuation, version tokens, and
  // filler words, repeatedly, until a non-filler word (the owner) remains.
  for (;;) {
    const before = pre;
    pre = pre.replace(/[\s,;:()\[\]]+$/, "");
    pre = pre.replace(/(?:v?\d[\d.]*(?:\.[x*])?|[–—-])$/i, "");
    const wm = pre.match(/([A-Za-z]+)$/);
    if (wm && ENUM_FILLER.has(wm[1].toLowerCase())) {
      pre = pre.slice(0, wm.index);
    }
    if (pre === before) break;
  }
  const tail = pre.slice(-48);
  if (!/[A-Za-z]/.test(tail)) return false; // hit a boundary — no clear owner
  if (matcher.test(tail)) return false; // our product owns the enumeration
  return true; // a different, concrete product owns these versions
}

// ---------------------------------------------------------------------------
// Structured "Affected Products" matching (NVD CPE / CNA version ranges).
// Authoritative and product-scoped, so it does not need the description
// heuristics. This is the only place OpenSSL 3.2.1 is recorded as affected by
// CVE-2024-4741, for instance.
// ---------------------------------------------------------------------------

function isRealVersion(v?: string): v is string {
  return !!v && /^\d/.test(v);
}

/** Whether `version` satisfies a single structured affected-version rule. */
function affectedRuleMatches(v: AffectedVersion, version: string): boolean {
  if (v.status && v.status !== "affected") return false;

  const lowerIncl = isRealVersion(v.version);
  const lowerExcl = isRealVersion(v.greaterThan);
  const upperExcl = isRealVersion(v.lessThan);
  const upperIncl = isRealVersion(v.lessThanOrEqual);

  // "*" / "-" with no upper bound → the whole product is affected.
  if ((v.version === "*" || v.version === "-") && !upperExcl && !upperIncl) {
    return true;
  }
  // A lone version with no bounds → that exact version only.
  if (lowerIncl && !lowerExcl && !upperExcl && !upperIncl) {
    return compareVersions(version, v.version!) === 0;
  }

  const anyBound = lowerIncl || lowerExcl || upperExcl || upperIncl;
  if (!anyBound) return false;

  if (lowerIncl && compareVersions(version, v.version!) < 0) return false;
  if (lowerExcl && compareVersions(version, v.greaterThan!) <= 0) return false;
  if (upperExcl && compareVersions(version, v.lessThan!) >= 0) return false;
  if (upperIncl && compareVersions(version, v.lessThanOrEqual!) > 0) return false;
  return true;
}

/** Whether the query product matches a structured affected-product entry. */
function affectedProductMatches(ap: AffectedProduct, matcher: RegExp): boolean {
  const candidates: string[] = [];
  if (ap.product) candidates.push(ap.product);
  if (ap.vendor) candidates.push(ap.vendor);
  for (const cpe of ap.cpes ?? []) {
    const product = cpe.split(":")[4]; // cpe:2.3:part:vendor:product:…
    if (product && product !== "*" && product !== "-") candidates.push(product);
  }
  return candidates.some((c) => matcher.test(c));
}

/** A human-readable description of a matched structured rule. */
function formatAffectedRule(ap: AffectedProduct, v: AffectedVersion): string {
  const name = ap.product || ap.vendor || "product";
  const lowerIncl = isRealVersion(v.version);
  const lowerExcl = isRealVersion(v.greaterThan);
  const upperExcl = isRealVersion(v.lessThan);
  const upperIncl = isRealVersion(v.lessThanOrEqual);

  if (lowerIncl && !lowerExcl && !upperExcl && !upperIncl) {
    return `${name} ${v.version}`;
  }
  let s = `${name} `;
  if (lowerIncl) s += `${v.version} ≤ `;
  else if (lowerExcl) s += `${v.greaterThan} < `;
  s += "version";
  if (upperExcl) s += ` < ${v.lessThan}`;
  else if (upperIncl) s += ` ≤ ${v.lessThanOrEqual}`;
  return s;
}

/**
 * Check the structured affected data for a confirmed, product-scoped match.
 * Returns the matching rule's evidence string, or null.
 */
function matchAffectedProducts(
  affected: AffectedProduct[] | undefined,
  matcher: RegExp,
  version: string
): string | null {
  for (const ap of affected ?? []) {
    if (!affectedProductMatches(ap, matcher)) continue;
    for (const v of ap.versions) {
      if (affectedRuleMatches(v, version)) return formatAffectedRule(ap, v);
    }
  }
  return null;
}

/**
 * Rank candidate records for a version query. A record is a confirmed match
 * when NVD's structured "Affected Products" data places the version in an
 * affected range for the queried product, OR the description places the version
 * inside an affected range AND the product phrase governs that range (is named
 * ahead of the clause).
 * Confirmed matches sort to the top; everything else is a best-effort fallback
 * ordered by product proximity, severity and KEV status. Every returned record
 * carries a `relevance` annotation.
 */
export function rankByVersionRelevance(
  records: VulnerabilityRecord[],
  version: string,
  product?: string
): VulnerabilityRecord[] {
  const productRe = buildProductMatcher(product);

  const scored = records.map((record) => {
    const desc = record.description;
    const { affected, evidence, matchIndex, matchLength } =
      evaluateDescription(desc, version);

    let productAnywhere = false;
    let productGoverns = false;
    let ownerConflict = false;
    let enumOwnerConflict = false;
    if (productRe) {
      productAnywhere = productRe.test(desc);
      if (matchIndex != null) {
        productGoverns = productGovernsClause(desc, matchIndex, productRe);
        ownerConflict = clauseOwnerConflict(
          desc,
          matchIndex + (matchLength ?? 0),
          productRe
        );
        enumOwnerConflict = enumerationOwnerConflict(desc, matchIndex, productRe);
      }
    }

    // Authoritative path: NVD's structured "Affected Products" data places the
    // version in an affected range for the queried product. This needs none of
    // the description heuristics (it is already product-scoped and exact), and
    // catches cases the prose omits — e.g. OpenSSL 3.2.1 / CVE-2024-4741.
    const cpeEvidence = productRe
      ? matchAffectedProducts(record.affected, productRe, version)
      : null;

    // Description path: the version is in a range AND the product governs the
    // matched clause — named in the clause's own (or the preceding) sentence,
    // the genuine subject (not merely "a <product> library"), the owner of the
    // version enumeration (not just mentioned elsewhere, e.g. inside a vuln name
    // like "OpenSSL 0-length" on a FortiOS CVE), with no different product
    // owning the clause. Without a product term we fall back to range-only.
    const descMatch =
      affected &&
      (productRe
        ? productGoverns &&
          productIsSubject(desc, productRe) &&
          !ownerConflict &&
          !enumOwnerConflict
        : true);

    const isMatch = cpeEvidence != null || descMatch;

    let score = 0;
    if (cpeEvidence != null) score += 1200;
    else if (descMatch) score += 1000;
    else if (productGoverns) score += 200;
    else if (productAnywhere) score += 60;
    if (desc.includes(version)) score += 40;
    score += record.cvssMetrics.primary.score; // 0–10 tie-breaker
    if (record.cisaKev.isKev) score += 5;

    const annotated: VulnerabilityRecord = {
      ...record,
      relevance: {
        matchedVersion: isMatch,
        evidence: cpeEvidence ?? (descMatch ? evidence : undefined),
        via: cpeEvidence != null ? "cpe" : descMatch ? "description" : undefined,
      },
    };
    return { record: annotated, score };
  });

  scored.sort((a, b) => b.score - a.score);
  return scored.map((s) => s.record);
}
