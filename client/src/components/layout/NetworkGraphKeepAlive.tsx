import { lazy, Suspense, useEffect, useState } from "react";
import { useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { PageLoader } from "@/components/states";

const NetworkExplorer = lazy(() => import("@/pages/NetworkExplorer"));

/**
 * Keeps Network Graph mounted after the first visit so LIVE capture, filters,
 * playback, and canvas state continue while the user browses other pages.
 */
export function NetworkGraphKeepAlive() {
  const [location] = useLocation();
  const onNetwork = location === "/network";
  const [visited, setVisited] = useState(onNetwork);

  useEffect(() => {
    if (onNetwork) setVisited(true);
  }, [onNetwork]);

  if (!visited) return null;

  return (
    <div
      className={cn(
        "flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden",
        !onNetwork && "hidden",
      )}
      aria-hidden={!onNetwork}
      // Keep canvas layout correct when returning from display:none
      data-network-keepalive=""
      data-active={onNetwork ? "true" : "false"}
    >
      <Suspense fallback={onNetwork ? <PageLoader label="Loading Network Graph…" /> : null}>
        <NetworkExplorer />
      </Suspense>
    </div>
  );
}
