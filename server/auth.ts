import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { createHash, randomBytes } from "crypto";
import type { Request, Response, NextFunction } from "express";
import { eq } from "drizzle-orm";
import { db } from "./db";
import { users, roles, sessions, auditLogs } from "@shared/schema";
import type { User, Role } from "@shared/schema";

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "dev-access-secret-change-in-production";
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "dev-refresh-secret-change-in-production";
const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES || "15m";
const REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES || "7d";

export interface AuthPayload {
  userId: string;
  email: string;
  role: string;
  permissions: string[];
}

export interface AuthenticatedRequest extends Request {
  user?: AuthPayload;
  dbUser?: User & { role: Role };
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function generateAccessToken(payload: AuthPayload): string {
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES as jwt.SignOptions["expiresIn"] });
}

export function generateRefreshToken(): string {
  return randomBytes(64).toString("hex");
}

export function verifyAccessToken(token: string): AuthPayload {
  return jwt.verify(token, ACCESS_SECRET) as AuthPayload;
}

export async function getUserWithRole(userId: string) {
  const result = await db
    .select({ user: users, role: roles })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id))
    .where(eq(users.id, userId))
    .limit(1);

  if (!result.length) return null;
  return { ...result[0].user, role: result[0].role };
}

export async function authenticate(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    const token = authHeader.slice(7);
    const payload = verifyAccessToken(token);
    const dbUser = await getUserWithRole(payload.userId);

    if (!dbUser || !dbUser.isActive) {
      res.status(401).json({ error: "Invalid or inactive user" });
      return;
    }

    req.user = payload;
    req.dbUser = dbUser;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

export function requirePermission(...permissions: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    const hasPermission = permissions.some((p) =>
      req.user!.permissions.includes(p) || req.user!.permissions.includes("*"),
    );

    if (!hasPermission && req.user.role !== "admin") {
      res.status(403).json({ error: "Insufficient permissions" });
      return;
    }

    next();
  };
}

export async function createAuditLog(params: {
  userId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}) {
  await db.insert(auditLogs).values({
    userId: params.userId,
    action: params.action,
    resource: params.resource,
    resourceId: params.resourceId,
    details: params.details ?? {},
    ipAddress: params.ipAddress,
    userAgent: params.userAgent,
  });
}

export async function createSession(userId: string, refreshToken: string, req: Request) {
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);

  await db.insert(sessions).values({
    userId,
    refreshTokenHash: hashToken(refreshToken),
    userAgent: req.headers["user-agent"] ?? undefined,
    ipAddress: req.ip,
    expiresAt,
  });
}

export async function revokeSession(refreshToken: string) {
  await db.delete(sessions).where(eq(sessions.refreshTokenHash, hashToken(refreshToken)));
}

export async function revokeAllUserSessions(userId: string) {
  await db.delete(sessions).where(eq(sessions.userId, userId));
}

export const PERMISSIONS = {
  ADMIN: "*",
  PREDICT: "predict",
  TRAIN: "train",
  MANAGE_USERS: "manage_users",
  MANAGE_DATASETS: "manage_datasets",
  MANAGE_ALERTS: "manage_alerts",
  VIEW_REPORTS: "view_reports",
  VIEW_DASHBOARD: "view_dashboard",
} as const;

export const ROLE_PERMISSIONS: Record<string, string[]> = {
  admin: [PERMISSIONS.ADMIN],
  analyst: [
    PERMISSIONS.PREDICT,
    PERMISSIONS.TRAIN,
    PERMISSIONS.MANAGE_ALERTS,
    PERMISSIONS.VIEW_REPORTS,
    PERMISSIONS.VIEW_DASHBOARD,
    PERMISSIONS.MANAGE_DATASETS,
  ],
  operator: [
    PERMISSIONS.PREDICT,
    PERMISSIONS.MANAGE_ALERTS,
    PERMISSIONS.VIEW_DASHBOARD,
  ],
  viewer: [PERMISSIONS.VIEW_DASHBOARD, PERMISSIONS.VIEW_REPORTS],
};
