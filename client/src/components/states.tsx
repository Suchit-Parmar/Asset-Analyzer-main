/**
 * Shared loading / error / empty UI states for Phase 5 polish.
 * Does not change API contracts — presentation only.
 */
import { Loader2, AlertTriangle, Inbox } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function PageLoader({ label = "Loading live data…" }: { label?: string }) {
  return (
    <div className="flex min-h-0 w-full flex-1 flex-col items-center justify-center gap-4 bg-background text-muted-foreground">
      <div className="relative flex h-14 w-14 items-center justify-center">
        <span className="absolute inset-0 rounded-full border border-primary/20" />
        <span className="absolute inset-0 rounded-full bg-primary/10 blur-md" />
        <Loader2 className="h-7 w-7 animate-spin text-primary" />
      </div>
      <p className="font-mono text-sm tracking-wide">{label}</p>
    </div>
  );
}

export function InlineLoader({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-8 text-muted-foreground">
      <Loader2 className="h-5 w-5 animate-spin text-primary" />
      {label && <span className="font-mono text-xs tracking-wide">{label}</span>}
    </div>
  );
}

export function ErrorState({
  title = "Unable to load data",
  message,
  onRetry,
}: {
  title?: string;
  message?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="panel-subtle flex flex-col items-center gap-4 p-8 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-full border border-yellow-400/20 bg-yellow-400/10">
        <AlertTriangle className="h-7 w-7 text-yellow-400" />
      </div>
      <div className="space-y-1.5">
        <div className="font-medium text-foreground">{title}</div>
        <p className="mx-auto max-w-md text-sm leading-relaxed text-muted-foreground">
          {message ?? "The API request failed. Check that Express and the AI service are running."}
        </p>
      </div>
      {onRetry && (
        <Button size="sm" variant="outline" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function EmptyState({
  title = "No data yet",
  message,
  className,
}: {
  title?: string;
  message?: string;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center gap-3 py-10 text-center text-muted-foreground", className)}>
      <div className="flex h-14 w-14 items-center justify-center rounded-full border border-white/8 bg-white/5">
        <Inbox className="h-7 w-7 opacity-60" />
      </div>
      <div className="font-medium text-foreground/80">{title}</div>
      {message && <p className="mx-auto max-w-md text-sm leading-relaxed">{message}</p>}
    </div>
  );
}
