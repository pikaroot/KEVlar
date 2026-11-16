import { AliasMapping } from "@/types/vulnerability";

/**
 * Known alias / branded-name dictionary.
 *
 * Keys are lowercased, whitespace-collapsed alias strings so that lookups can be
 * performed case-insensitively (see `resolveAlias`). Each alias maps to one OR
 * MORE canonical CVE IDs — several branded vulnerabilities (ProxyLogon,
 * ProxyShell, PHP2SHELL) are exploit chains spanning multiple CVEs.
 */
export const VULN_ALIASES: Record<string, AliasMapping> = {
  php2shell: {
    cveIds: ["CVE-2026-109618", "CVE-2026-109619"],
    displayName: "PHP2SHELL",
  },
  log4shell: { cveIds: ["CVE-2021-44228"], displayName: "Log4Shell" },
  heartbleed: { cveIds: ["CVE-2014-0160"], displayName: "Heartbleed" },
  eternalblue: { cveIds: ["CVE-2017-0144"], displayName: "EternalBlue" },
  proxylogon: {
    cveIds: [
      "CVE-2021-26855",
      "CVE-2021-26857",
      "CVE-2021-26858",
      "CVE-2021-27065",
    ],
    displayName: "ProxyLogon",
  },
  proxyshell: {
    cveIds: ["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
    displayName: "ProxyShell",
  },
  zerologon: { cveIds: ["CVE-2020-1472"], displayName: "ZeroLogon" },
  spring4shell: { cveIds: ["CVE-2022-22965"], displayName: "Spring4Shell" },
  dirtycow: { cveIds: ["CVE-2016-5195"], displayName: "Dirty COW" },
  pwnkit: { cveIds: ["CVE-2021-4034"], displayName: "PwnKit" },
  bluekeep: { cveIds: ["CVE-2019-0708"], displayName: "BlueKeep" },
  regresshion: { cveIds: ["CVE-2024-6387"], displayName: "regreSSHion" },
  poodle: { cveIds: ["CVE-2014-3566"], displayName: "POODLE" },
  // Extra well-known aliases for a richer dictionary.
  shellshock: { cveIds: ["CVE-2014-6271"], displayName: "Shellshock" },
  "baron samedit": { cveIds: ["CVE-2021-3156"], displayName: "Baron Samedit" },
  sudobaron: { cveIds: ["CVE-2021-3156"], displayName: "Baron Samedit" },
  follina: { cveIds: ["CVE-2022-30190"], displayName: "Follina" },
  text4shell: { cveIds: ["CVE-2022-42889"], displayName: "Text4Shell" },
  citrixbleed: { cveIds: ["CVE-2023-4966"], displayName: "CitrixBleed" },
  "looney tunables": {
    cveIds: ["CVE-2023-4911"],
    displayName: "Looney Tunables",
  },
  looney: { cveIds: ["CVE-2023-4911"], displayName: "Looney Tunables" },
};

/** Normalize an alias key for case-insensitive, whitespace-tolerant matching. */
export function normalizeAliasKey(input: string): string {
  return input.trim().toLowerCase().replace(/\s+/g, " ");
}

/**
 * Resolve a free-text query against the alias dictionary.
 * Tries the raw normalized key, then a space-stripped variant so that
 * "Dirty COW" and "dirtycow" both resolve.
 */
export function resolveAlias(input: string): AliasMapping | null {
  const key = normalizeAliasKey(input);
  if (VULN_ALIASES[key]) return VULN_ALIASES[key];

  const collapsed = key.replace(/\s+/g, "");
  if (VULN_ALIASES[collapsed]) return VULN_ALIASES[collapsed];

  return null;
}

/** Reverse lookup: given a canonical CVE ID, return its display name if known. */
export function brandedNameForCve(cveId: string): string | null {
  const target = cveId.trim().toUpperCase();
  for (const mapping of Object.values(VULN_ALIASES)) {
    if (mapping.cveIds.some((id) => id.toUpperCase() === target)) {
      return mapping.displayName;
    }
  }
  return null;
}

/** Curated list for the suggestion chips shown under the search bar. */
export const SUGGESTION_CHIPS: Array<{ label: string; query: string }> = [
  { label: "PHP2SHELL", query: "PHP2SHELL" },
  { label: "Log4Shell", query: "Log4Shell" },
  { label: "ProxyLogon", query: "ProxyLogon" },
  { label: "POODLE", query: "POODLE" },
  { label: "php 8.0.39", query: "php 8.0.39" },
  { label: "openssl 1.0.1", query: "openssl 1.0.1" },
  { label: "regreSSHion", query: "regreSSHion" },
  { label: "CVE-2024-6387", query: "CVE-2024-6387" },
];
