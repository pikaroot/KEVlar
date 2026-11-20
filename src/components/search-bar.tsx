"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Search, Loader2, X, Tag, Package, Hash } from "lucide-react";
import { SUGGESTION_CHIPS } from "@/lib/alias-dictionary";
import { getSuggestions, Suggestion } from "@/lib/suggestions";
import { cn } from "@/lib/utils";

const KIND_ICON = {
  alias: Tag,
  product: Package,
  cve: Hash,
} as const;

export function SearchBar({
  onSearch,
  isLoading,
  initialValue = "",
}: {
  onSearch: (query: string) => void;
  isLoading: boolean;
  initialValue?: string;
}) {
  const [value, setValue] = useState(initialValue);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const inputRef = useRef<HTMLInputElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Close the dropdown on an outside click.
  useEffect(() => {
    function onDocClick(e: MouseEvent) {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, []);

  const suggestions = useMemo<Suggestion[]>(
    () => (open ? getSuggestions(value) : []),
    [value, open]
  );

  function submit(q: string) {
    const trimmed = q.trim();
    if (!trimmed) return;
    setOpen(false);
    setActive(-1);
    onSearch(trimmed);
  }

  function choose(s: Suggestion) {
    setValue(s.value);
    setActive(-1);
    if (s.submit) {
      submit(s.value);
    } else {
      // Product chosen — keep the dropdown open so the next keystrokes (the
      // version) refine, and refocus the input at the end.
      setOpen(true);
      requestAnimationFrame(() => {
        const el = inputRef.current;
        if (el) {
          el.focus();
          el.setSelectionRange(s.value.length, s.value.length);
        }
      });
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (!open || suggestions.length === 0) {
      if (e.key === "ArrowDown" && value.trim()) setOpen(true);
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => (i + 1) % suggestions.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => (i <= 0 ? suggestions.length - 1 : i - 1));
    } else if (e.key === "Enter") {
      if (active >= 0 && active < suggestions.length) {
        e.preventDefault();
        choose(suggestions[active]);
      }
    } else if (e.key === "Escape") {
      setOpen(false);
      setActive(-1);
    } else if (e.key === "Tab" && active >= 0) {
      e.preventDefault();
      choose(suggestions[active]);
    }
  }

  return (
    <div className="w-full" ref={boxRef}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit(value);
        }}
        className="relative"
      >
        <Search className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-zinc-500" />
        <input
          ref={inputRef}
          type="text"
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setOpen(true);
            setActive(-1);
          }}
          onFocus={() => value.trim() && setOpen(true)}
          onKeyDown={onKeyDown}
          placeholder="CVE-2024-4577, PHP2SHELL, php 8.0.39, or a keyword…"
          spellCheck={false}
          autoComplete="off"
          role="combobox"
          aria-expanded={open && suggestions.length > 0}
          aria-controls="search-suggestions"
          aria-activedescendant={active >= 0 ? `suggestion-${active}` : undefined}
          aria-label="Vulnerability search"
          className="w-full rounded-xl border border-zinc-700 bg-zinc-900/80 py-4 pl-12 pr-28 font-mono text-base text-zinc-100 shadow-lg outline-none transition placeholder:text-zinc-600 focus:border-indigo-500/60 focus:ring-2 focus:ring-indigo-500/20"
        />
        <div className="absolute right-2 top-1/2 flex -translate-y-1/2 items-center gap-1">
          {value && !isLoading && (
            <button
              type="button"
              onClick={() => {
                setValue("");
                setOpen(false);
                inputRef.current?.focus();
              }}
              className="rounded-md p-2 text-zinc-500 transition hover:text-zinc-300"
              aria-label="Clear"
            >
              <X className="h-4 w-4" />
            </button>
          )}
          <button
            type="submit"
            disabled={isLoading || !value.trim()}
            className={cn(
              "inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition",
              "bg-indigo-500 text-zinc-950 hover:bg-indigo-400",
              "disabled:cursor-not-allowed disabled:opacity-50"
            )}
          >
            {isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Search className="h-4 w-4" />
            )}
            <span className="hidden sm:inline">Search</span>
          </button>
        </div>

        {/* Autocomplete dropdown */}
        {open && suggestions.length > 0 && (
          <ul
            id="search-suggestions"
            role="listbox"
            className="absolute z-20 mt-2 w-full overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950/95 shadow-2xl backdrop-blur"
          >
            {suggestions.map((s, i) => {
              const Icon = KIND_ICON[s.kind];
              return (
                <li
                  key={s.value}
                  id={`suggestion-${i}`}
                  role="option"
                  aria-selected={i === active}
                  onMouseEnter={() => setActive(i)}
                  onMouseDown={(e) => {
                    e.preventDefault(); // keep input focus
                    choose(s);
                  }}
                  className={cn(
                    "flex cursor-pointer items-center gap-3 px-4 py-2.5 text-sm",
                    i === active ? "bg-indigo-500/15 text-zinc-100" : "text-zinc-300"
                  )}
                >
                  <Icon
                    className={cn(
                      "h-4 w-4 flex-shrink-0",
                      s.kind === "alias"
                        ? "text-rose-400"
                        : s.kind === "cve"
                        ? "text-indigo-400"
                        : "text-emerald-400"
                    )}
                  />
                  <span className="truncate font-mono">{s.label}</span>
                  {s.detail && (
                    <span className="ml-auto flex-shrink-0 font-mono text-xs text-zinc-600">
                      {s.detail}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </form>

      {/* Suggestion chips */}
      <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
        <span className="text-xs text-zinc-600">Try:</span>
        {SUGGESTION_CHIPS.map((chip) => (
          <button
            key={chip.query}
            type="button"
            onClick={() => {
              setValue(chip.query);
              submit(chip.query);
            }}
            disabled={isLoading}
            className="rounded border border-zinc-800 bg-zinc-900/60 px-3 py-1 font-mono text-xs text-zinc-400 transition hover:border-indigo-500/40 hover:bg-indigo-500/10 hover:text-indigo-300 disabled:opacity-50"
          >
            {chip.label}
          </button>
        ))}
      </div>
    </div>
  );
}
