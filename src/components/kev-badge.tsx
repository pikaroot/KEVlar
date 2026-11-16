import { ShieldAlert, Biohazard } from "lucide-react";
import { KevMetadata } from "@/types/vulnerability";
import { Badge } from "@/components/ui/badge";
import { formatDate } from "@/lib/utils";

/** The pulsing crimson "exploited in the wild" badge. */
export function KevBadge() {
  return (
    <Badge className="animate-kev-pulse border-rose-500/50 bg-rose-600 text-white">
      <ShieldAlert className="h-3.5 w-3.5" />
      CISA KEV · Exploited in the Wild
    </Badge>
  );
}

/** Detailed KEV panel shown inside the result card when listed. */
export function KevPanel({ kev }: { kev: KevMetadata }) {
  if (!kev.isKev) return null;
  const ransomKnown = kev.knownRansomwareCampaignUse === "Known";
  return (
    <div className="rounded-lg border border-rose-500/30 bg-rose-950/30 p-4">
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-rose-300">
        <ShieldAlert className="h-4 w-4" />
        CISA Known Exploited Vulnerability
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-4">
        <Field label="Date Added" value={formatDate(kev.dateAdded)} />
        <Field label="Remediation Due" value={formatDate(kev.dueDate)} />
        <div className="col-span-2 sm:col-span-2">
          <dt className="text-xs uppercase tracking-wider text-zinc-500">
            Ransomware Use
          </dt>
          <dd
            className={
              "mt-0.5 inline-flex items-center gap-1.5 font-medium " +
              (ransomKnown ? "text-rose-300" : "text-zinc-300")
            }
          >
            {ransomKnown && <Biohazard className="h-4 w-4" />}
            {kev.knownRansomwareCampaignUse ?? "Unknown"}
          </dd>
        </div>
      </dl>
      {kev.requiredAction && (
        <div className="mt-3 border-t border-rose-500/20 pt-3">
          <dt className="text-xs uppercase tracking-wider text-zinc-500">
            Required Action
          </dt>
          <dd className="mt-1 text-sm leading-relaxed text-zinc-200">
            {kev.requiredAction}
          </dd>
        </div>
      )}
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-zinc-500">{label}</dt>
      <dd className="mt-0.5 font-mono font-medium text-zinc-200">{value}</dd>
    </div>
  );
}
