/** Loading placeholder shown while a lookup is in flight. */
export function SkeletonCard() {
  return (
    <div className="animate-pulse rounded-xl border border-zinc-800 bg-zinc-900/60 p-6">
      <div className="flex items-center justify-between">
        <div className="h-6 w-40 rounded bg-zinc-800" />
        <div className="h-8 w-8 rounded bg-zinc-800" />
      </div>
      <div className="mt-3 flex gap-2">
        <div className="h-5 w-28 rounded bg-zinc-800" />
        <div className="h-5 w-32 rounded bg-zinc-800" />
      </div>
      <div className="mt-5 space-y-2">
        <div className="h-3 w-full rounded bg-zinc-800" />
        <div className="h-3 w-11/12 rounded bg-zinc-800" />
        <div className="h-3 w-3/4 rounded bg-zinc-800" />
      </div>
      <div className="mt-6 flex gap-2 border-t border-zinc-800 pt-4">
        <div className="h-8 w-28 rounded bg-zinc-800" />
        <div className="h-8 w-32 rounded bg-zinc-800" />
        <div className="h-8 w-28 rounded bg-zinc-800" />
      </div>
    </div>
  );
}
