import { useEffect, useRef } from "react";
import { useLocation } from "wouter";

const STORAGE_KEY = "aa:scroll-positions";
const MAX_RESTORE_ATTEMPTS = 80;

type PositionMap = Record<string, number>;

function readPositions(): PositionMap {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return {};
    return parsed as PositionMap;
  } catch {
    return {};
  }
}

function writePosition(path: string, y: number) {
  try {
    const map = readPositions();
    map[path] = Math.max(0, Math.round(y));
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(map));
  } catch {
    // sessionStorage may be unavailable; ignore
  }
}

function clearPosition(path: string) {
  try {
    const map = readPositions();
    delete map[path];
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(map));
  } catch {
    // ignore
  }
}

/** App pages scroll inside `<main class="… overflow-auto">`, not the window. */
export function findPageScrollContainer(): HTMLElement | null {
  const candidates = Array.from(
    document.querySelectorAll<HTMLElement>("main.app-main, main.overflow-auto, main.flex-1"),
  );
  // Prefer the visible page — Network Graph may stay mounted but hidden (keep-alive).
  const visible = candidates.find((el) => {
    if (el.closest("[data-network-keepalive][data-active='false']")) return false;
    return el.getClientRects().length > 0;
  });
  return visible ?? null;
}

function isHardReload(): boolean {
  try {
    const entry = performance.getEntriesByType("navigation")[0] as
      | PerformanceNavigationTiming
      | undefined;
    return entry?.type === "reload";
  } catch {
    return false;
  }
}

/**
 * Persists per-route scroll positions for the page main container.
 * Restores when revisiting a route (Back/Forward or sidebar return).
 * Fresh routes and hard reloads start at the top.
 */
export function ScrollRestoration() {
  const [location] = useLocation();
  const locationRef = useRef(location);
  const skipNextRestoreRef = useRef(false);

  useEffect(() => {
    if ("scrollRestoration" in window.history) {
      window.history.scrollRestoration = "manual";
    }
  }, []);

  // Hard refresh: start at top for the current route (do not re-apply old offset).
  useEffect(() => {
    if (isHardReload()) {
      clearPosition(location);
      skipNextRestoreRef.current = true;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only on mount
  }, []);

  // Keep saving the active container's scrollTop for the current path.
  useEffect(() => {
    locationRef.current = location;
    let el: HTMLElement | null = null;
    let rafBind = 0;
    let debounceTimer: ReturnType<typeof setTimeout> | undefined;
    let cancelled = false;

    const save = () => {
      if (!el || cancelled) return;
      writePosition(locationRef.current, el.scrollTop);
    };

    const onScroll = () => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(save, 50);
    };

    const bind = () => {
      if (cancelled) return;
      const next = findPageScrollContainer();
      if (next !== el) {
        if (el) el.removeEventListener("scroll", onScroll);
        el = next;
        if (el) {
          el.addEventListener("scroll", onScroll, { passive: true });
        }
      }
      if (!el) {
        rafBind = requestAnimationFrame(bind);
      }
    };

    bind();

    return () => {
      cancelAnimationFrame(rafBind);
      if (debounceTimer) clearTimeout(debounceTimer);
      if (el) {
        writePosition(locationRef.current, el.scrollTop);
        el.removeEventListener("scroll", onScroll);
      }
      cancelled = true;
    };
  }, [location]);

  // Restore (or reset) when the route changes.
  useEffect(() => {
    if (skipNextRestoreRef.current) {
      skipNextRestoreRef.current = false;
      let attempts = 0;
      const resetTop = () => {
        const el = findPageScrollContainer();
        if (!el) {
          if (attempts++ < MAX_RESTORE_ATTEMPTS) requestAnimationFrame(resetTop);
          return;
        }
        el.scrollTop = 0;
      };
      requestAnimationFrame(resetTop);
      return;
    }

    const target = readPositions()[location] ?? 0;
    let attempts = 0;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const apply = () => {
      if (cancelled) return;
      const el = findPageScrollContainer();
      if (!el) {
        if (attempts++ < MAX_RESTORE_ATTEMPTS) {
          raf = requestAnimationFrame(apply);
        }
        return;
      }

      el.scrollTop = target;

      // Wait for async page content to grow tall enough for the saved offset.
      if (
        target > 0 &&
        el.scrollHeight < target + el.clientHeight &&
        attempts++ < MAX_RESTORE_ATTEMPTS
      ) {
        raf = requestAnimationFrame(apply);
        return;
      }
    };

    let raf = requestAnimationFrame(apply);
    // Extra pass after lazy/Suspense + data fetch settle.
    timer = setTimeout(() => {
      attempts = 0;
      apply();
    }, 120);

    return () => {
      cancelled = true;
      cancelAnimationFrame(raf);
      if (timer) clearTimeout(timer);
    };
  }, [location]);

  return null;
}
