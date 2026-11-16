import {
  CalendarX2,
  ArrowUpCircle,
  ShieldCheck,
  HelpCircle,
  ExternalLink,
} from "lucide-react";
import { EolStatus } from "@/types/vulnerability";

const STYLES: Record<
  EolStatus["level"],
  { wrap: string; icon: string; label: string; Icon: typeof CalendarX2 }
> = {
  eol: {
    wrap: "border-rose-500/40 bg-rose-950/30 text-rose-100",
    icon: "text-rose-400",
    label: "End-of-life",
    Icon: CalendarX2,
  },
  outdated: {
    wrap: "border-amber-500/40 bg-amber-950/25 text-amber-100",
    icon: "text-amber-400",
    label: "Update available",
    Icon: ArrowUpCircle,
  },
  supported: {
    wrap: "border-emerald-500/40 bg-emerald-950/25 text-emerald-100",
    icon: "text-emerald-400",
    label: "Supported",
    Icon: ShieldCheck,
  },
  unknown: {
    wrap: "border-zinc-700 bg-zinc-900/50 text-zinc-300",
    icon: "text-zinc-400",
    label: "Lifecycle unknown",
    Icon: HelpCircle,
  },
};

export function EolBanner({ eol }: { eol: EolStatus }) {
  const s = STYLES[eol.level];
  const { Icon } = s;

  return (
    <div className={`rounded-xl border px-4 py-3.5 ${s.wrap}`}>
      <div className="flex items-start gap-3">
        <Icon className={`mt-0.5 h-5 w-5 flex-shrink-0 ${s.icon}`} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="text-sm font-semibold">
              {s.label}
              {eol.cycle ? ` · ${eol.product} ${eol.cycle}` : ` · ${eol.product}`}
            </span>
            {eol.level === "eol" && eol.eolDate && (
              <span className="rounded-full bg-black/30 px-2 py-0.5 font-mono text-[11px]">
                EOL {eol.eolDate}
              </span>
            )}
          </div>

          <p className="mt-1 text-sm leading-relaxed opacity-90">
            {eol.recommendation}
          </p>

          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] opacity-80">
            {eol.latestInCycle && (
              <span>
                branch latest:{" "}
                <span className="font-semibold">{eol.latestInCycle}</span>
              </span>
            )}
            {eol.latestOverall && (
              <span>
                newest:{" "}
                <span className="font-semibold">{eol.latestOverall}</span>
              </span>
            )}
            <a
              href={eol.sourceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 underline decoration-dotted underline-offset-2 hover:opacity-100"
            >
              lifecycle <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
