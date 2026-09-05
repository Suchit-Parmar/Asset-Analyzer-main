import type { Express } from "express";
import { createServer, type Server } from "http";
import authRoutes from "./routes/auth.routes";
import apiRoutes from "./routes/api.routes";
import { setupSecurity } from "./middleware/security";
import { setupWebSocket } from "./websocket";
import { seedDatabase } from "./seed";
import { syncNetworkFromDataset } from "./sync-network";

export async function registerRoutes(httpServer: Server, app: Express): Promise<Server> {
  setupSecurity(app);

  app.use("/api/auth", authRoutes);
  app.use("/api", apiRoutes);

  try {
    await seedDatabase();
    await syncNetworkFromDataset();
  } catch (error) {
    console.warn("[routes] Initialization skipped (database/AI may not be ready):", error);
  }

  setupWebSocket(httpServer);

  return httpServer;
}
