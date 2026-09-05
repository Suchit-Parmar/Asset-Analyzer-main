import { Sidebar } from "@/components/layout/Sidebar";

/**
 * Persistent chrome for authenticated routes.
 * Sidebar stays mounted across page navigations so nav scroll position is preserved.
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="app-shell flex h-screen bg-background text-foreground overflow-hidden">
      <Sidebar />
      <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
        {children}
      </div>
    </div>
  );
}
