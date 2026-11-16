import { VulnerabilityRecord } from "@/types/vulnerability";

/** Format the primary CVSS score, falling back to "N/A" when unscored. */
function primaryScoreLabel(vuln: VulnerabilityRecord): string {
  const s = vuln.cvssMetrics.primary.score;
  return s > 0 ? s.toFixed(1) : "N/A";
}

/**
 * Primary Reference Copy — standard single-line report reference:
 *   [CVE-ID] (CVSS X.X - SEVERITY) - Description
 */
export function formatQuickCopy(vuln: VulnerabilityRecord): string {
  const score = primaryScoreLabel(vuln);
  return `[${vuln.cveId}] (CVSS ${score} - ${vuln.cvssMetrics.primary.severity}) - ${vuln.description}`;
}

/**
 * Named Reference Copy — includes the branded alias when one exists:
 *   [CVE-ID / NAME] (CVSS X.X - SEVERITY) - Description
 */
export function formatNamedCopy(vuln: VulnerabilityRecord): string {
  const namePart = vuln.brandedName ? ` / ${vuln.brandedName}` : "";
  const score = primaryScoreLabel(vuln);
  return `[${vuln.cveId}${namePart}] (CVSS ${score} - ${vuln.cvssMetrics.primary.severity}) - ${vuln.description}`;
}

/** Quick CVE ID Copy — just the identifier string. */
export function formatCveIdCopy(vuln: VulnerabilityRecord): string {
  return vuln.cveId;
}

/**
 * Markdown Export Copy — structured block for reports and tickets, including
 * the full CVSS matrix, KEV status, and the official NVD source link.
 */
export function formatMarkdownReport(vuln: VulnerabilityRecord): string {
  const primary = vuln.cvssMetrics.primary;
  const primaryScore = primary.score > 0 ? primary.score.toFixed(1) : "N/A";

  const cvssList = vuln.cvssMetrics.all
    .map(
      (m) =>
        `    - **v${m.version}:** ${m.score.toFixed(1)} (${m.severity}) - \`${
          m.vectorString || "N/A"
        }\``
    )
    .join("\n");

  const lines = [
    `### [${vuln.cveId}](${vuln.nvdUrl})${
      vuln.brandedName ? ` (${vuln.brandedName})` : ""
    }`,
    `- **Primary Severity:** CVSS ${primaryScore} (${primary.severity}) [v${primary.version}]`,
    `- **All CVSS Metrics:**${cvssList ? `\n${cvssList}` : " N/A"}`,
    `- **In CISA KEV:** ${
      vuln.cisaKev.isKev ? "YES (Active Exploitation)" : "No"
    }`,
  ];

  if (vuln.cisaKev.isKev) {
    if (vuln.cisaKev.dateAdded)
      lines.push(`- **KEV Date Added:** ${vuln.cisaKev.dateAdded}`);
    if (vuln.cisaKev.dueDate)
      lines.push(`- **Remediation Due:** ${vuln.cisaKev.dueDate}`);
    if (vuln.cisaKev.knownRansomwareCampaignUse)
      lines.push(
        `- **Known Ransomware Use:** ${vuln.cisaKev.knownRansomwareCampaignUse}`
      );
  }

  if (vuln.weaknesses.length > 0) {
    lines.push(`- **Weaknesses:** ${vuln.weaknesses.join(", ")}`);
  }

  lines.push(`- **Description:** ${vuln.description}`);
  lines.push(`- **Published:** ${vuln.publishedDate}`);
  lines.push(`- **Official Source:** [NVD Reference](${vuln.nvdUrl})`);

  if (vuln.references.length > 0) {
    lines.push(`- **References:**`);
    for (const r of vuln.references.slice(0, 3)) {
      lines.push(`  - [${r.source}](${r.url})`);
    }
  }

  return lines.join("\n");
}
