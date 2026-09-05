import { Link, useLocation } from "wouter";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Boxes,
  Brain,
  ChevronsLeft,
  FileText,
  FlaskConical,
  LayoutDashboard,
  Menu,
  Network,
  ScanSearch,
  Shield,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import { useIsMobile } from "@/hooks/use-mobile";

const SIDEBAR_SCROLL_KEY = "aa:sidebar-nav-scroll";

/** Backup scroll memory if Sidebar ever remounts (primary fix: AppShell keeps it mounted). */
let sidebarNavScrollY = 0;

function readSidebarScroll(): number {
  if (sidebarNavScrollY > 0) return sidebarNavScrollY;
  try {
    const raw = sessionStorage.getItem(SIDEBAR_SCROLL_KEY);
    const n = raw ? Number(raw) : 0;
    return Number.isFinite(n) && n > 0 ? n : 0;
  } catch {
    return 0;
  }
}

function writeSidebarScroll(y: number) {
  const next = Math.max(0, Math.round(y));
  sidebarNavScrollY = next;
  try {
    sessionStorage.setItem(SIDEBAR_SCROLL_KEY, String(next));
  } catch {
    // ignore
  }
}

const SIDEBAR_SECTIONS: Array<{
  title: string;
  items: Array<{
    href: string;
    label: string;
    icon: typeof LayoutDashboard;
    hint: string;
  }>;
}> = [
  {
    title: "Command",
    items: [
      { href: "/", label: "Overview", icon: LayoutDashboard, hint: "Network health & SOC pulse" },
      { href: "/network", label: "Network Graph", icon: Network, hint: "Dynamic timestamp graph" },
      { href: "/suspects", label: "Potential Suspects", icon: AlertTriangle, hint: "Suspicious devices" },
      { href: "/alerts", label: "Threat Detection", icon: Shield, hint: "Incidents and alerts" },
      { href: "/network-scanner", label: "Devices", icon: ScanSearch, hint: "Hosts, IoT & inventory" },
    ],
  },
  {
    title: "Insights",
    items: [
      { href: "/attack-intelligence", label: "Threat Journey", icon: Zap, hint: "Attack progression storyline" },
      { href: "/explainability", label: "AI Explainability", icon: Brain, hint: "Model reasoning layers" },
      { href: "/risk-assessment", label: "Risk Radar", icon: Activity, hint: "Exposure at a glance" },
      { href: "/evaluation", label: "Analytics", icon: BarChart3, hint: "Model & traffic metrics" },
    ],
  },
  {
    title: "Research",
    items: [
      { href: "/experiment", label: "Model Studio", icon: Network, hint: "Training and tuning" },
      { href: "/models", label: "Model Registry", icon: Boxes, hint: "Checkpoints and versions" },
      { href: "/research", label: "Research Lab", icon: FlaskConical, hint: "Continual learning & drift" },
      { href: "/advanced-eval", label: "Deep Metrics", icon: Activity, hint: "Extended analytics" },
      { href: "/admin", label: "Admin Panel", icon: Activity, hint: "System management" },
      { href: "/files", label: "Project Atlas", icon: FileText, hint: "Files and architecture" },
    ],
  },
];

export function Sidebar() {
  const [location] = useLocation();
  const isMobile = useIsMobile();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const navRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    setMobileOpen(false);
  }, [location]);

  useEffect(() => {
    if (isMobile) {
      setCollapsed(false);
    } else {
      setMobileOpen(false);
    }
  }, [isMobile]);

  // Preserve COMMAND / Insights / Research nav scroll across navigations.
  // AppShell keeps Sidebar mounted; this is a backup if remount still happens.
  useLayoutEffect(() => {
    const el = navRef.current;
    if (!el) return;
    const saved = readSidebarScroll();
    if (saved > 0 && Math.abs(el.scrollTop - saved) > 1) {
      el.scrollTop = saved;
    }
  }, [location, collapsed, isMobile]);

  useEffect(() => {
    const el = navRef.current;
    if (!el) return;

    const onScroll = () => writeSidebarScroll(el.scrollTop);
    el.addEventListener("scroll", onScroll, { passive: true });

    // Restore once more after paint (fonts / layout settle).
    const saved = readSidebarScroll();
    if (saved > 0) {
      requestAnimationFrame(() => {
        if (navRef.current) navRef.current.scrollTop = saved;
      });
    }

    return () => {
      writeSidebarScroll(el.scrollTop);
      el.removeEventListener("scroll", onScroll);
    };
  }, [collapsed, isMobile]);

  const allItems = useMemo(
    () => SIDEBAR_SECTIONS.flatMap((section) => section.items),
    [],
  );
  const currentItem = allItems.find((item) => item.href === location) ?? allItems[0];
  const isCompact = !isMobile && collapsed;

  return (
    <>
      {isMobile && (
        <>
          <button
            type="button"
            onClick={() => setMobileOpen(true)}
            className="fixed left-4 top-4 z-50 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-border/60 bg-card/95 text-foreground shadow-lg backdrop-blur"
            aria-label="Open navigation"
          >
            <Menu size={18} />
          </button>
          <div className="fixed left-20 top-4 z-40 hidden rounded-full border border-border/60 bg-card/90 px-4 py-2 text-xs font-mono text-muted-foreground shadow-lg backdrop-blur sm:block">
            <span className="text-primary">ACTIVE</span> {currentItem.label}
          </div>
        </>
      )}

      {isMobile && mobileOpen && (
        <button
          type="button"
          aria-label="Close navigation overlay"
          className="fixed inset-0 z-40 bg-background/70 backdrop-blur-sm"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={cn(
          "h-screen border-r border-border/60 bg-[linear-gradient(180deg,rgba(12,18,28,0.98),rgba(10,14,22,0.92))] text-foreground transition-all duration-300",
          "flex flex-col",
          isMobile
            ? cn(
                "fixed inset-y-0 left-0 z-50 w-[292px] shadow-2xl",
                mobileOpen ? "translate-x-0" : "-translate-x-full",
              )
            : isCompact
              ? "w-20"
              : "w-72",
        )}
      >
        <div className={cn("border-b border-border/60", isCompact ? "px-3 py-4" : "px-5 py-5")}>
          <div className={cn("flex items-start", isCompact ? "justify-center" : "justify-between gap-3")}>
            <div className={cn("flex items-center gap-3", isCompact && "justify-center")}>
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-primary/25 bg-primary/10 shadow-[0_0_30px_rgba(34,211,238,0.12)]">
                <Shield className="h-5 w-5 text-primary" />
              </div>
              {!isCompact && (
                <div>
                  <div className="font-mono text-lg font-semibold tracking-tight text-white">GNN-IDS</div>
                  <div className="text-xs text-muted-foreground">Cyber intelligence workspace</div>
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={() => (isMobile ? setMobileOpen(false) : setCollapsed((value) => !value))}
              className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-transparent text-muted-foreground transition-colors hover:border-border/60 hover:bg-white/5 hover:text-foreground"
              aria-label={isMobile ? "Close navigation" : collapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {isMobile ? <X size={18} /> : <ChevronsLeft className={cn("transition-transform", collapsed && "rotate-180")} size={18} />}
            </button>
          </div>

          {!isCompact && (
            <div className="mt-5 rounded-2xl border border-border/60 bg-white/[0.03] p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <span className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground">Now Viewing</span>
                <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-[10px] font-mono text-emerald-300">
                  ONLINE
                </span>
              </div>
              <div className="text-sm font-semibold text-white">{currentItem.label}</div>
              <div className="mt-1 text-xs text-muted-foreground">{currentItem.hint}</div>
            </div>
          )}
        </div>

        <nav
          ref={navRef}
          data-sidebar-nav="true"
          className={cn(
            "flex-1 overflow-y-auto overscroll-contain [overflow-anchor:none]",
            isCompact ? "px-2 py-4" : "px-3 py-5",
          )}
        >
          {SIDEBAR_SECTIONS.map((section) => (
            <div key={section.title} className="mb-5 last:mb-0">
              {!isCompact && (
                <div className="mb-2 px-3 text-[11px] font-medium uppercase tracking-[0.18em] text-muted-foreground/80">
                  {section.title}
                </div>
              )}

              <div className="space-y-1.5">
                {section.items.map((link) => {
                  const Icon = link.icon;
                  const isActive = location === link.href;

                  return (
                    <Link key={link.href} href={link.href}>
                      <div
                        className={cn(
                          "group relative flex cursor-pointer items-center rounded-2xl border transition-all duration-200",
                          isCompact ? "justify-center px-0 py-3" : "gap-3 px-3.5 py-3",
                          isActive
                            ? "border-primary/25 bg-primary/[0.12] text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.04),0_0_22px_rgba(34,211,238,0.08)]"
                            : "border-transparent text-muted-foreground hover:border-border/60 hover:bg-white/[0.04] hover:text-foreground",
                        )}
                        title={isCompact ? link.label : undefined}
                      >
                        <div
                          className={cn(
                            "flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border transition-colors",
                            isActive
                              ? "border-primary/20 bg-primary/10 text-primary"
                              : "border-white/5 bg-white/[0.03] text-muted-foreground group-hover:text-foreground",
                          )}
                        >
                          <Icon size={17} />
                        </div>

                        {!isCompact && (
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-sm font-medium">{link.label}</div>
                            <div className="truncate text-xs text-muted-foreground/80">{link.hint}</div>
                          </div>
                        )}

                        {isActive && <div className="absolute inset-y-3 left-0 w-1 rounded-r-full bg-primary" />}
                      </div>
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className={cn("border-t border-border/60", isCompact ? "p-3" : "p-4")}>
          {!isCompact ? (
            <div className="rounded-2xl border border-border/60 bg-black/20 p-4">
              <div className="mb-3 flex items-center gap-2 text-xs font-mono text-primary">
                <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_12px_rgba(74,222,128,0.8)]" />
                SYSTEM READY
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <div className="text-muted-foreground">Latency</div>
                  <div className="mt-1 font-mono text-white">12 ms</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Feed</div>
                  <div className="mt-1 font-mono text-white">Live</div>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex justify-center">
              <div className="h-10 w-10 rounded-xl border border-emerald-500/20 bg-emerald-500/10 text-emerald-300 flex items-center justify-center">
                <Activity size={16} />
              </div>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
