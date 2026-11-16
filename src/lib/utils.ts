/** Tiny classnames joiner (no external dependency). */
export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

import { CvssSeverity } from "@/types/vulnerability";

/** Tailwind classes for the severity badge, per the spec's color map. */
export function severityClasses(severity: CvssSeverity): string {
  switch (severity) {
    case "CRITICAL":
      return "bg-red-500/10 text-red-400 border-red-500/30";
    case "HIGH":
      return "bg-orange-500/10 text-orange-400 border-orange-500/30";
    case "MEDIUM":
      return "bg-amber-500/10 text-amber-400 border-amber-500/30";
    case "LOW":
      return "bg-blue-500/10 text-blue-400 border-blue-500/30";
    default:
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/30";
  }
}

/** Accent ring color used for the card's left edge. */
export function severityAccent(severity: CvssSeverity): string {
  switch (severity) {
    case "CRITICAL":
      return "before:bg-red-500";
    case "HIGH":
      return "before:bg-orange-500";
    case "MEDIUM":
      return "before:bg-amber-500";
    case "LOW":
      return "before:bg-blue-500";
    default:
      return "before:bg-zinc-600";
  }
}

/** Format an ISO date string to a short, stable, locale-independent label. */
export function formatDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}
