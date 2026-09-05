import { lazy, Suspense, useState, useEffect } from "react";
import { Switch, Route, Redirect, useLocation } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { PageLoader } from "@/components/states";
import { ScrollRestoration } from "@/components/ScrollRestoration";
import { AppShell } from "@/components/layout/AppShell";
import { NetworkGraphKeepAlive } from "@/components/layout/NetworkGraphKeepAlive";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import NotFound from "@/pages/not-found";
import { api } from "@/lib/api";

const Experiment = lazy(() => import("@/pages/Experiment"));
const Evaluation = lazy(() => import("@/pages/Evaluation"));
const AttackIntelligence = lazy(() => import("@/pages/AttackIntelligence"));
const Explainability = lazy(() => import("@/pages/Explainability"));
const RiskAssessment = lazy(() => import("@/pages/RiskAssessment"));
const AdvancedEvaluation = lazy(() => import("@/pages/AdvancedEvaluation"));
const NetworkScanner = lazy(() => import("@/pages/NetworkScanner"));
const Suspects = lazy(() => import("@/pages/Suspects"));
const AlertCenter = lazy(() => import("@/pages/AlertCenter"));
const AdminPanel = lazy(() => import("@/pages/AdminPanel"));
const ModelRegistry = lazy(() => import("@/pages/ModelRegistry"));
const ResearchDashboard = lazy(() => import("@/pages/ResearchDashboard"));
const ProjectStructure = lazy(() => import("@/pages/ProjectStructure"));

function AuthenticatedApp({ onLogout }: { onLogout: () => void }) {
  const [location] = useLocation();
  const onNetwork = location === "/network";

  return (
    <AppShell>
      {/* Network Graph stays mounted in the background after first visit */}
      <NetworkGraphKeepAlive />

      {!onNetwork && (
        <Suspense fallback={<PageLoader label="Loading page…" />}>
          <Switch>
            <Route path="/login"><Redirect to="/" /></Route>
            <Route path="/"><Dashboard onLogout={onLogout} /></Route>
            <Route path="/suspects" component={Suspects} />
            <Route path="/experiment" component={Experiment} />
            <Route path="/models" component={ModelRegistry} />
            <Route path="/research" component={ResearchDashboard} />
            <Route path="/evaluation" component={Evaluation} />
            <Route path="/attack-intelligence" component={AttackIntelligence} />
            <Route path="/explainability" component={Explainability} />
            <Route path="/risk-assessment" component={RiskAssessment} />
            <Route path="/advanced-eval" component={AdvancedEvaluation} />
            <Route path="/network-scanner" component={NetworkScanner} />
            <Route path="/alerts" component={AlertCenter} />
            <Route path="/admin" component={AdminPanel} />
            <Route path="/files" component={ProjectStructure} />
            <Route component={NotFound} />
          </Switch>
        </Suspense>
      )}
    </AppShell>
  );
}

function Router() {
  const [isAuthenticated, setIsAuthenticated] = useState(() => !!api.getAccessToken());

  useEffect(() => {
    if (!api.getAccessToken()) {
      setIsAuthenticated(false);
      return;
    }
    api.getMe()
      .then(() => setIsAuthenticated(true))
      .catch(() => {
        api.clearTokens();
        setIsAuthenticated(false);
      });
  }, []);

  const handleLogin = () => setIsAuthenticated(true);

  const handleLogout = async () => {
    // Stop background live capture when leaving the authenticated session.
    await api.stopLive().catch(() => undefined);
    await api.logout();
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return (
      <Switch>
        <Route path="/login"><Login onLogin={handleLogin} /></Route>
        <Route path="/"><Redirect to="/login" /></Route>
        <Route component={NotFound} />
      </Switch>
    );
  }

  return <AuthenticatedApp onLogout={handleLogout} />;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <ScrollRestoration />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
