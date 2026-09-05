import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cors from "cors";
import type { Express } from "express";

export function setupSecurity(app: Express) {
  const isDev = process.env.NODE_ENV !== "production";

  app.use(helmet({
    contentSecurityPolicy: isDev ? false : undefined,
    crossOriginEmbedderPolicy: false,
  }));

  app.use(cors({
    origin: isDev
      ? true
      : (process.env.CORS_ORIGIN || "http://localhost:5000"),
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }));

  // Auth routes have their own limiter; skip them here to avoid double-counting.
  const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "900000", 10),
    max: isDev ? 10000 : parseInt(process.env.RATE_LIMIT_MAX || "100", 10),
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests, please try again later" },
    skip: (req) => req.path.startsWith("/auth"),
  });

  app.use("/api/", limiter);

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isDev ? 1000 : 20,
    message: { error: "Too many authentication attempts" },
  });

  app.use("/api/auth/login", authLimiter);
  app.use("/api/auth/register", authLimiter);
}
