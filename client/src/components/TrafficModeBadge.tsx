import { cn } from "@/lib/utils";

export type TrafficMode = "live" | "replay" | "awaiting";

const COPY: Record<TrafficMode, { label: string; hint: string; className: string; dot: string }> = {
  live: {
    label: "● LIVE DETECTION",
    hint: "LIVE = Authorized Local Network Monitoring",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    dot: "bg-emerald-400 animate-pulse",
  },
  replay: {
    label: "● DATASET REPLAY",
    hint: "DATASET REPLAY = Historical/Demo Traffic",
    className: "border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
    dot: "bg-cyan-400 animate-pulse",
  },
  awaiting: {
    label: "AWAITING DATA",
    hint: "No topology loaded yet",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    dot: "bg-amber-400",
  },
};

export function TrafficModeBadge({
  mode,
  className,
  showHint = true,
}: {
  mode: TrafficMode;
  className?: string;
  showHint?: boolean;
}) {
  const c = COPY[mode];
  return (
    <div className={cn("inline-flex flex-col gap-0.5", className)}>
      <div
        className={cn(
          "inline-flex items-center gap-1.5 rounded border px-2 py-1 text-[10px] font-mono tracking-wide",
          c.className,
        )}
      >
        <span className={cn("h-1.5 w-1.5 rounded-full", c.dot)} />
        {c.label}
      </div>
      {showHint && <span className="text-[10px] text-muted-foreground font-mono">{c.hint}</span>}
    </div>
  );
}
