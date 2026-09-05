import { type Express } from "express";
import { createServer as createViteServer, createLogger } from "vite";
import { type Server } from "http";
import viteConfig from "../vite.config";
import fs from "fs";
import path from "path";
import { nanoid } from "nanoid";

const viteLogger = createLogger();

export async function setupVite(server: Server, app: Express) {
  // The app already attaches `ws` to this HTTP server for `/ws`. Sharing that
  // same server for Vite HMR causes upgrade conflicts (browser: "WebSocket
  // closed without opened" / HTTP 400 on `/vite-hmr`). Run HMR on a dedicated
  // port instead, and point the client at it explicitly.
  //
  // Do not use Vite's default 5173 — nothing listens there in this setup
  // (Express+Vite middleware is on PORT, usually 5000).
  const hmrPort = parseInt(process.env.VITE_HMR_PORT || "24678", 10);
  const serverOptions = {
    middlewareMode: true,
    hmr: {
      path: "/vite-hmr",
      port: hmrPort,
      clientPort: hmrPort,
    },
    allowedHosts: true as const,
  };

  const vite = await createViteServer({
    ...viteConfig,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      },
    },
    server: serverOptions,
    appType: "custom",
  });

  // `server` is the Express HTTP server (used by callers for middleware mode).
  // HMR intentionally does not attach to it — see hmr.port above.
  void server;

  app.use(vite.middlewares);

  app.use("*", async (req, res, next) => {
    const url = req.originalUrl;

    try {
      const clientTemplate = path.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html",
      );

      // always reload the index.html file from disk incase it changes
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`,
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e as Error);
      next(e);
    }
  });
}
