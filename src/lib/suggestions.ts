import { VULN_ALIASES } from "@/lib/alias-dictionary";

/**
 * Lightweight, fully client-side type-ahead for the search box. Predicts what
 * the user is typing from three sources — branded/alias names, common product
 * names, and CVE-ID shaping — ranked prefix-first. No network calls.
 */

export interface Suggestion {
  /** Text inserted into the input when chosen. */
  value: string;
  /** Display label. */
  label: string;
  kind: "alias" | "product" | "cve";
  /** Small secondary hint shown on the right. */
  detail?: string;
  /** Whether choosing this should run the search immediately (vs. keep typing). */
  submit: boolean;
}

// Common technologies people look up by "<product> <version>". Kept in sync by
// hand; the version is supplied by the user, so only the product name matters.
const PRODUCTS: string[] = [
  "openssl", "openssh", "php", "python", "node.js", "go", "ruby", "rust",
  "java", "dotnet", "perl",
  "apache", "apache tomcat", "nginx", "httpd", "iis", "haproxy", "envoy",
  "mysql", "mariadb", "postgresql", "mongodb", "redis", "elasticsearch",
  "sqlite", "oracle database", "microsoft sql server",
  "wordpress", "drupal", "joomla", "magento",
  "django", "laravel", "symfony", "rails", "spring", "spring boot",
  "express", "flask", "struts",
  "jquery", "jquery ui", "react", "angular", "angularjs", "vue", "bootstrap",
  "axios", "lodash", "next.js", "webpack",
  "log4j", "log4net", "jackson", "commons-collections",
  "docker", "kubernetes", "containerd", "helm", "istio",
  "jenkins", "gitlab", "grafana", "prometheus", "terraform", "ansible",
  "curl", "wget", "git", "vim", "sudo", "bash", "glibc", "systemd",
  "openvpn", "wireguard", "strongswan", "fortios", "openfortivpn",
  "exim", "postfix", "dovecot", "bind", "unbound", "samba", "squid",
  "jenkins", "sonarqube", "nextcloud", "owncloud", "gitea",
];

// Dedupe product list while keeping order.
const PRODUCT_LIST = Array.from(new Set(PRODUCTS));

// Distinct branded/alias display names with their primary CVE.
const ALIAS_LIST: Array<{ name: string; detail: string }> = (() => {
  const seen = new Set<string>();
  const out: Array<{ name: string; detail: string }> = [];
  for (const m of Object.values(VULN_ALIASES)) {
    if (seen.has(m.displayName)) continue;
    seen.add(m.displayName);
    const detail =
      m.cveIds.length > 1 ? `${m.cveIds[0]} +${m.cveIds.length - 1}` : m.cveIds[0];
    out.push({ name: m.displayName, detail });
  }
  return out;
})();

/** Rank: 0 = prefix match (best), 1 = word-boundary, 2 = substring, -1 = none. */
function matchRank(haystack: string, q: string): number {
  const h = haystack.toLowerCase();
  if (h.startsWith(q)) return 0;
  if (new RegExp(`\\b${q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`).test(h)) return 1;
  if (h.includes(q)) return 2;
  return -1;
}

export function getSuggestions(input: string, limit = 7): Suggestion[] {
  const q = input.trim().toLowerCase();
  if (q.length < 1) return [];

  // Typing a CVE id — offer to complete the canonical shape.
  const cveLike = q.match(/^(?:cve[-\s]?)?(\d{4})[-\s]?(\d{0,7})$/i);
  const scored: Array<{ s: Suggestion; rank: number; len: number }> = [];

  if (cveLike && (q.startsWith("cve") || q.length >= 4)) {
    const year = cveLike[1];
    const num = cveLike[2];
    const value = num ? `CVE-${year}-${num}` : `CVE-${year}-`;
    scored.push({
      s: { value, label: value, kind: "cve", detail: "CVE identifier", submit: !!num && num.length >= 4 },
      rank: 0,
      len: value.length,
    });
  }

  for (const a of ALIAS_LIST) {
    const r = matchRank(a.name, q);
    if (r < 0) continue;
    scored.push({
      s: { value: a.name, label: a.name, kind: "alias", detail: a.detail, submit: true },
      rank: r,
      len: a.name.length,
    });
  }

  // Only suggest products for the first token (don't fight a version the user
  // is typing after the product name).
  const firstToken = q.split(/\s+/)[0];
  for (const p of PRODUCT_LIST) {
    const r = matchRank(p, firstToken);
    if (r < 0) continue;
    scored.push({
      s: {
        value: `${p} `,
        label: p,
        kind: "product",
        detail: "add a version",
        submit: false,
      },
      rank: r,
      len: p.length,
    });
  }

  scored.sort((a, b) => a.rank - b.rank || a.len - b.len || a.s.label.localeCompare(b.s.label));

  // De-duplicate by value.
  const seen = new Set<string>();
  const out: Suggestion[] = [];
  for (const { s } of scored) {
    if (seen.has(s.value.toLowerCase())) continue;
    seen.add(s.value.toLowerCase());
    out.push(s);
    if (out.length >= limit) break;
  }
  return out;
}
