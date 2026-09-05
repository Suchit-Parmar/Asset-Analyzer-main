import { FormEvent, useState } from "react";
import { Fingerprint, LockKeyhole, ShieldCheck } from "lucide-react";

import { toast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSeparator,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { api } from "@/lib/api";

type AuthTab = "signin" | "signup";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [activeTab, setActiveTab] = useState<AuthTab>("signin");
  const [signInEmail, setSignInEmail] = useState("admin@gnn-ids.local");
  const [signInPassword, setSignInPassword] = useState("Admin@123456");
  const [signUpName, setSignUpName] = useState("");
  const [signUpEmail, setSignUpEmail] = useState("");
  const [signUpPassword, setSignUpPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [otpToken, setOtpToken] = useState("");
  const [pendingTotpEmail, setPendingTotpEmail] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function completeLogin(email: string, password: string, totpCode?: string) {
    const result = await api.login(email, password, totpCode);
    if (result.requiresTotp) {
      setPendingTotpEmail(result.email ?? email);
      toast({
        title: "2FA required",
        description: "Enter the 6-digit code from your authenticator app.",
      });
      return false;
    }
    if (!result.accessToken) {
      throw new Error("Login succeeded but no access token was returned");
    }
    return true;
  }

  async function handleSignIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!signInEmail.trim() || !signInPassword) {
      toast({ title: "Missing credentials", description: "Enter your email and password.", variant: "destructive" });
      return;
    }

    setIsSubmitting(true);
    try {
      const ok = await completeLogin(signInEmail.trim(), signInPassword);
      if (ok) {
        toast({ title: "Authenticated", description: "JWT session established with the Express API." });
        onLogin();
      }
    } catch (err) {
      toast({
        title: "Login failed",
        description: err instanceof Error ? err.message : "Unknown error",
        variant: "destructive",
      });
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleTotpSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!pendingTotpEmail || otpToken.length !== 6) {
      toast({ title: "Invalid code", description: "Enter the current 6-digit TOTP code.", variant: "destructive" });
      return;
    }

    setIsSubmitting(true);
    try {
      const ok = await completeLogin(pendingTotpEmail, signInPassword, otpToken);
      if (ok) {
        setPendingTotpEmail(null);
        setOtpToken("");
        toast({ title: "Verified", description: "2FA accepted. Entering Mission Control." });
        onLogin();
      }
    } catch (err) {
      toast({
        title: "2FA failed",
        description: err instanceof Error ? err.message : "Unknown error",
        variant: "destructive",
      });
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleSignUp(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!signUpName.trim() || !signUpEmail.trim() || !signUpPassword || !confirmPassword) {
      toast({ title: "Incomplete sign up", description: "Fill in all fields.", variant: "destructive" });
      return;
    }
    if (signUpPassword.length < 8) {
      toast({ title: "Password too short", description: "Use at least 8 characters.", variant: "destructive" });
      return;
    }
    if (signUpPassword !== confirmPassword) {
      toast({ title: "Passwords do not match", description: "Re-enter the same password.", variant: "destructive" });
      return;
    }

    setIsSubmitting(true);
    try {
      await api.register(signUpName.trim(), signUpEmail.trim(), signUpPassword);
      const ok = await completeLogin(signUpEmail.trim(), signUpPassword);
      if (ok) {
        toast({ title: "Account created", description: "Registered against PostgreSQL and signed in." });
        onLogin();
      } else {
        setSignInEmail(signUpEmail.trim());
        setSignInPassword(signUpPassword);
        setActiveTab("signin");
      }
    } catch (err) {
      toast({
        title: "Sign up failed",
        description: err instanceof Error ? err.message : "Unknown error",
        variant: "destructive",
      });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="relative min-h-screen overflow-hidden px-4 py-8 sm:px-6 lg:px-8">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.14),transparent_26%),radial-gradient(circle_at_80%_15%,rgba(59,130,246,0.1),transparent_22%),linear-gradient(180deg,rgba(2,6,23,0.86),rgba(2,8,18,1))]" />

      <div className="relative mx-auto flex min-h-[calc(100vh-4rem)] max-w-7xl items-center">
        <div className="grid w-full gap-6 lg:grid-cols-[1.12fr_0.88fr]">
          <section className="panel-card relative overflow-hidden p-6 sm:p-8 lg:p-10">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.14),transparent_30%),linear-gradient(135deg,rgba(255,255,255,0.04),rgba(255,255,255,0))]" />
            <div className="relative space-y-8">
              <div className="space-y-4">
                <div className="page-kicker">Secure Access Layer</div>
                <h1 className="max-w-2xl text-4xl font-semibold text-white sm:text-5xl">
                  Operator access via JWT-backed Express authentication.
                </h1>
                <p className="max-w-xl text-sm leading-7 text-slate-300 sm:text-base">
                  Phase 4 uses real PostgreSQL users and Bearer tokens. Dashboard APIs and live
                  WebSocket updates require a valid session from the Express backend.
                </p>
              </div>

              <div className="grid gap-4 md:grid-cols-3">
                <div className="panel-subtle space-y-3 p-4">
                  <ShieldCheck className="h-5 w-5 text-cyan-300" />
                  <div className="font-mono text-sm uppercase tracking-[0.16em] text-slate-100">JWT Login</div>
                  <p className="text-sm leading-6 text-slate-300">Credentials validated by `/api/auth/login`.</p>
                </div>
                <div className="panel-subtle space-y-3 p-4">
                  <LockKeyhole className="h-5 w-5 text-cyan-300" />
                  <div className="font-mono text-sm uppercase tracking-[0.16em] text-slate-100">RBAC</div>
                  <p className="text-sm leading-6 text-slate-300">Protected predict, alert, and topology routes.</p>
                </div>
                <div className="panel-subtle space-y-3 p-4">
                  <Fingerprint className="h-5 w-5 text-cyan-300" />
                  <div className="font-mono text-sm uppercase tracking-[0.16em] text-slate-100">Live WS</div>
                  <p className="text-sm leading-6 text-slate-300">WebSocket uses the same access token.</p>
                </div>
              </div>

              <div className="panel-subtle space-y-3 p-5">
                <div className="font-mono text-sm uppercase tracking-[0.16em] text-slate-100">Seeded Admin</div>
                <div className="rounded-2xl border border-white/8 bg-black/20 p-4 text-sm text-slate-200">
                  <div>Email: <span className="font-mono text-cyan-200">admin@gnn-ids.local</span></div>
                  <div>Password: <span className="font-mono text-cyan-200">Admin@123456</span></div>
                </div>
              </div>
            </div>
          </section>

          <section className="panel-card overflow-hidden p-6 sm:p-8">
            {pendingTotpEmail ? (
              <form className="space-y-6" onSubmit={handleTotpSubmit}>
                <div className="space-y-2">
                  <div className="font-mono text-sm uppercase tracking-[0.16em] text-cyan-200">Authenticator Check</div>
                  <h2 className="text-2xl font-semibold text-white">Enter the current 6-digit code</h2>
                  <p className="text-sm text-slate-400">2FA is enabled for {pendingTotpEmail}.</p>
                </div>
                <InputOTP maxLength={6} value={otpToken} onChange={setOtpToken} containerClassName="justify-center">
                  <InputOTPGroup>
                    <InputOTPSlot index={0} />
                    <InputOTPSlot index={1} />
                    <InputOTPSlot index={2} />
                  </InputOTPGroup>
                  <InputOTPSeparator />
                  <InputOTPGroup>
                    <InputOTPSlot index={3} />
                    <InputOTPSlot index={4} />
                    <InputOTPSlot index={5} />
                  </InputOTPGroup>
                </InputOTP>
                <Button className="w-full" size="lg" type="submit" disabled={isSubmitting}>
                  Verify and continue
                </Button>
                <Button type="button" variant="ghost" className="w-full" onClick={() => setPendingTotpEmail(null)}>
                  Back
                </Button>
              </form>
            ) : (
              <div className="space-y-6">
                <div className="space-y-2">
                  <div className="font-mono text-sm uppercase tracking-[0.16em] text-cyan-200">Identity Checkpoint</div>
                  <h2 className="text-2xl font-semibold text-white">Access the operator console</h2>
                  <p className="text-sm leading-6 text-slate-400">
                    Sign in against the Express + PostgreSQL auth service.
                  </p>
                </div>

                <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as AuthTab)} className="space-y-6">
                  <TabsList className="grid h-auto w-full grid-cols-2 rounded-2xl bg-white/6 p-1">
                    <TabsTrigger value="signin" className="rounded-xl py-2.5">Sign In</TabsTrigger>
                    <TabsTrigger value="signup" className="rounded-xl py-2.5">Sign Up</TabsTrigger>
                  </TabsList>

                  <TabsContent value="signin" className="mt-0">
                    <form className="space-y-5" onSubmit={handleSignIn}>
                      <div className="space-y-2">
                        <Label htmlFor="signin-email">Email</Label>
                        <Input
                          id="signin-email"
                          type="email"
                          value={signInEmail}
                          onChange={(e) => setSignInEmail(e.target.value)}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="signin-password">Password</Label>
                        <Input
                          id="signin-password"
                          type="password"
                          value={signInPassword}
                          onChange={(e) => setSignInPassword(e.target.value)}
                        />
                      </div>
                      <Button className="w-full" size="lg" type="submit" disabled={isSubmitting}>
                        {isSubmitting ? "Signing in..." : "Sign in with JWT"}
                      </Button>
                    </form>
                  </TabsContent>

                  <TabsContent value="signup" className="mt-0">
                    <form className="space-y-5" onSubmit={handleSignUp}>
                      <div className="space-y-2">
                        <Label htmlFor="signup-name">Full name</Label>
                        <Input id="signup-name" value={signUpName} onChange={(e) => setSignUpName(e.target.value)} />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="signup-email">Email</Label>
                        <Input id="signup-email" type="email" value={signUpEmail} onChange={(e) => setSignUpEmail(e.target.value)} />
                      </div>
                      <div className="grid gap-5 sm:grid-cols-2">
                        <div className="space-y-2">
                          <Label htmlFor="signup-password">Password</Label>
                          <Input id="signup-password" type="password" value={signUpPassword} onChange={(e) => setSignUpPassword(e.target.value)} />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="signup-confirm">Confirm</Label>
                          <Input id="signup-confirm" type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
                        </div>
                      </div>
                      <Button className="w-full" size="lg" type="submit" disabled={isSubmitting}>
                        Create account
                      </Button>
                    </form>
                  </TabsContent>
                </Tabs>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
