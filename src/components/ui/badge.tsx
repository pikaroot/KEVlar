import { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function Badge({
  children,
  className,
  mono = false,
}: {
  children: ReactNode;
  className?: string;
  mono?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-wide",
        mono && "font-mono",
        className
      )}
    >
      {children}
    </span>
  );
}
