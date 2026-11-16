"use client";

import { useState, useCallback, ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/utils";
import { useToast } from "@/components/ui/toast";
import { Tooltip } from "@/components/ui/tooltip";

/**
 * Multi-use clipboard button. Clicking copies `value`, flips the icon to a
 * checkmark for 2 seconds, and raises a toast.
 */
export function CopyButton({
  value,
  label,
  toastLabel,
  tooltip,
  icon,
  variant = "ghost",
}: {
  value: string;
  label?: ReactNode;
  toastLabel: string;
  tooltip?: string;
  icon?: ReactNode;
  variant?: "ghost" | "solid";
}) {
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const onCopy = useCallback(async () => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        // Fallback for non-secure contexts (e.g. plain http://localhost mirror).
        const ta = document.createElement("textarea");
        ta.value = value;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      setCopied(true);
      toast(`${toastLabel} copied to clipboard`, "success");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast("Copy failed — check clipboard permissions", "error");
    }
  }, [value, toastLabel, toast]);

  const button = (
    <button
      type="button"
      onClick={onCopy}
      aria-label={typeof label === "string" ? label : toastLabel}
      className={cn(
        "inline-flex items-center gap-2 rounded-md border text-sm font-medium transition-colors",
        label ? "px-3 py-1.5" : "p-2",
        variant === "solid"
          ? "border-indigo-500/40 bg-indigo-500/15 text-indigo-200 hover:bg-indigo-500/25"
          : "border-zinc-700 bg-zinc-800/60 text-zinc-300 hover:border-zinc-600 hover:bg-zinc-800 hover:text-zinc-100",
        copied && "border-emerald-500/50 text-emerald-300"
      )}
    >
      <span className="relative inline-flex h-4 w-4 items-center justify-center">
        {copied ? (
          <Check className="h-4 w-4" />
        ) : (
          icon ?? <Copy className="h-4 w-4" />
        )}
      </span>
      {label}
    </button>
  );

  if (tooltip) {
    return <Tooltip label={tooltip}>{button}</Tooltip>;
  }
  return button;
}
