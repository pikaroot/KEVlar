/**
 * Smart input resolution helpers.
 *
 * Classifies a raw user query into one of three intents and, for CVE inputs,
 * normalizes loose formats like `cve 2024 4577` or `2024-4577` into the
 * canonical `CVE-2024-4577` form.
 */

export type QueryKind = "cve-id" | "alias-or-keyword";

/**
 * Attempt to normalize a loose CVE-ish string to canonical form.
 * Returns null when the input does not look like a CVE identifier.
 *
 * Accepts:
 *   CVE-2024-4577, cve-2024-4577, cve 2024 4577, cve_2024_4577,
 *   2024-4577, 2024 4577
 */
export function normalizeCveId(input: string): string | null {
  const cleaned = input.trim();

  // Match an optional CVE prefix, a 4-digit year, and a 4+ digit sequence,
  // separated by hyphens, spaces or underscores.
  const match = cleaned.match(
    /^(?:cve[\s_-]*)?(\d{4})[\s_-]+(\d{4,7})$/i
  );
  if (!match) return null;

  const [, year, seq] = match;
  return `CVE-${year}-${seq}`;
}

/** True when the input resolves to a canonical CVE identifier. */
export function isCveId(input: string): boolean {
  return normalizeCveId(input) !== null;
}
