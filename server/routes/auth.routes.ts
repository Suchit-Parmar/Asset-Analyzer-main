import { Router } from "express";
import { eq } from "drizzle-orm";
import { OTP } from "otplib";
import QRCode from "qrcode";
import { db } from "../db";
import { users, roles } from "@shared/schema";
import { loginSchema, registerSchema } from "@shared/schema";
import {
  authenticate,
  createAuditLog,
  createSession,
  generateAccessToken,
  generateRefreshToken,
  getUserWithRole,
  hashPassword,
  hashToken,
  revokeAllUserSessions,
  revokeSession,
  ROLE_PERMISSIONS,
  verifyPassword,
  type AuthenticatedRequest,
} from "../auth";
import { sessions } from "@shared/schema";

const router = Router();
const otp = new OTP({ strategy: "totp" });

router.post("/register", async (req, res) => {
  try {
    const body = registerSchema.parse(req.body);

    const existing = await db.select().from(users).where(eq(users.email, body.email.toLowerCase())).limit(1);
    if (existing.length) {
      res.status(409).json({ error: "Email already registered" });
      return;
    }

    const [analystRole] = await db.select().from(roles).where(eq(roles.name, "analyst")).limit(1);
    if (!analystRole) {
      res.status(500).json({ error: "System not initialized. Run seed script." });
      return;
    }

    const passwordHash = await hashPassword(body.password);
    const [user] = await db.insert(users).values({
      email: body.email.toLowerCase(),
      name: body.name,
      passwordHash,
      roleId: analystRole.id,
      totpSecret: otp.generateSecret(),
    }).returning();

    await createAuditLog({
      userId: user.id,
      action: "register",
      resource: "users",
      resourceId: user.id,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.status(201).json({
      message: "Registration successful",
      user: { id: user.id, email: user.email, name: user.name },
    });
  } catch (error) {
    if (error instanceof Error && error.name === "ZodError") {
      res.status(400).json({ error: "Invalid registration data" });
      return;
    }
    res.status(500).json({ error: "Registration failed" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const body = loginSchema.parse(req.body);
    const email = body.email.toLowerCase();

    const dbUser = await getUserWithRole(
      (await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1))[0]?.id ?? "",
    );

    if (!dbUser || !(await verifyPassword(body.password, dbUser.passwordHash))) {
      res.status(401).json({ error: "Invalid email or password" });
      return;
    }

    if (!dbUser.isActive) {
      res.status(403).json({ error: "Account is deactivated" });
      return;
    }

    if (dbUser.totpEnabled) {
      if (!body.totpCode) {
        res.status(200).json({ requiresTotp: true, email: dbUser.email });
        return;
      }
      const result = otp.verifySync({
        secret: dbUser.totpSecret!,
        token: body.totpCode,
        digits: 6,
        period: 30,
        epochTolerance: 30,
      });
      if (!result.valid) {
        res.status(401).json({ error: "Invalid 2FA code" });
        return;
      }
    }

    const permissions = ROLE_PERMISSIONS[dbUser.role.name] ?? [];
    const accessToken = generateAccessToken({
      userId: dbUser.id,
      email: dbUser.email,
      role: dbUser.role.name,
      permissions,
    });
    const refreshToken = generateRefreshToken();
    await createSession(dbUser.id, refreshToken, req);

    await db.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, dbUser.id));

    await createAuditLog({
      userId: dbUser.id,
      action: "login",
      resource: "sessions",
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: dbUser.id,
        email: dbUser.email,
        name: dbUser.name,
        role: dbUser.role.name,
        totpEnabled: dbUser.totpEnabled,
        permissions,
      },
    });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

router.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      res.status(400).json({ error: "Refresh token required" });
      return;
    }

    const [session] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.refreshTokenHash, hashToken(refreshToken)))
      .limit(1);

    if (!session || session.expiresAt < new Date()) {
      res.status(401).json({ error: "Invalid or expired refresh token" });
      return;
    }

    const dbUser = await getUserWithRole(session.userId);
    if (!dbUser || !dbUser.isActive) {
      res.status(401).json({ error: "User not found or inactive" });
      return;
    }

    const permissions = ROLE_PERMISSIONS[dbUser.role.name] ?? [];
    const accessToken = generateAccessToken({
      userId: dbUser.id,
      email: dbUser.email,
      role: dbUser.role.name,
      permissions,
    });

    res.json({ accessToken });
  } catch {
    res.status(500).json({ error: "Token refresh failed" });
  }
});

router.post("/logout", authenticate, async (req: AuthenticatedRequest, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) await revokeSession(refreshToken);
  await createAuditLog({
    userId: req.user!.userId,
    action: "logout",
    resource: "sessions",
    ipAddress: req.ip,
  });
  res.json({ message: "Logged out" });
});

router.get("/me", authenticate, async (req: AuthenticatedRequest, res) => {
  const dbUser = await getUserWithRole(req.user!.userId);
  if (!dbUser) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  res.json({
    id: dbUser.id,
    email: dbUser.email,
    name: dbUser.name,
    role: dbUser.role.name,
    totpEnabled: dbUser.totpEnabled,
    permissions: ROLE_PERMISSIONS[dbUser.role.name] ?? [],
    lastLoginAt: dbUser.lastLoginAt,
  });
});

router.post("/totp/setup", authenticate, async (req: AuthenticatedRequest, res) => {
  const dbUser = await getUserWithRole(req.user!.userId);
  if (!dbUser?.totpSecret) {
    res.status(400).json({ error: "TOTP not configured" });
    return;
  }

  const otpauthUrl = otp.generateURI({
    issuer: "GNN-IDS",
    label: dbUser.email,
    secret: dbUser.totpSecret,
    digits: 6,
    period: 30,
    algorithm: "sha1",
  });

  const qrCode = await QRCode.toDataURL(otpauthUrl);
  res.json({ qrCode, secret: dbUser.totpSecret, otpauthUrl });
});

router.post("/totp/verify", authenticate, async (req: AuthenticatedRequest, res) => {
  const { code } = req.body;
  const dbUser = await getUserWithRole(req.user!.userId);
  if (!dbUser?.totpSecret) {
    res.status(400).json({ error: "TOTP not configured" });
    return;
  }

  const result = otp.verifySync({
    secret: dbUser.totpSecret,
    token: code,
    digits: 6,
    period: 30,
    epochTolerance: 30,
  });

  if (!result.valid) {
    res.status(400).json({ error: "Invalid TOTP code" });
    return;
  }

  await db.update(users).set({ totpEnabled: true }).where(eq(users.id, dbUser.id));
  res.json({ message: "2FA enabled successfully" });
});

router.post("/totp/disable", authenticate, async (req: AuthenticatedRequest, res) => {
  const { password, code } = req.body;
  const dbUser = await getUserWithRole(req.user!.userId);
  if (!dbUser || !(await verifyPassword(password, dbUser.passwordHash))) {
    res.status(401).json({ error: "Invalid password" });
    return;
  }

  const result = otp.verifySync({
    secret: dbUser.totpSecret!,
    token: code,
    digits: 6,
    period: 30,
    epochTolerance: 30,
  });

  if (!result.valid) {
    res.status(400).json({ error: "Invalid TOTP code" });
    return;
  }

  await db.update(users).set({ totpEnabled: false, totpSecret: otp.generateSecret() }).where(eq(users.id, dbUser.id));
  await revokeAllUserSessions(dbUser.id);
  res.json({ message: "2FA disabled" });
});

export default router;
