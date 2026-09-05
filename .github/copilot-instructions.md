# Asset Analyzer - Copilot Instructions

## Project Overview
Asset Analyzer is a **Temporal Graph Neural Network (TGNN) security research prototype** for intrusion detection and attack stage prediction. It features a full-stack TypeScript application with a React + Tailwind frontend for dashboards (Dashboard, Experiment Lab, Attack Intelligence, Explainability, Risk Assessment, Evaluation, Advanced Metrics) and an Express.js backend with PostgreSQL database.

## Architecture & Critical Patterns

### Monorepo Structure
- **`client/`**: React frontend (Vite build, client-side routing via Wouter)
- **`server/`**: Express.js backend with request logging middleware
- **`shared/`**: Drizzle ORM schema and Zod validators (used by both client/server)
- **`script/`**: Build orchestration (esbuild for server, Vite for client)

### Data Flow
1. Frontend pages render dashboards using mock data (`client/src/lib/advancedMockData.ts`, `mockData.ts`)
2. Routes defined in `App.tsx` → `client/src/pages/` (8 page components)
3. Backend routes added in `server/routes.ts` (prefix `/api` for all routes)
4. Database schema in `shared/schema.ts` uses Drizzle ORM with PostgreSQL

### Build & Dev Workflow
- **Development**: Parallel processes via `npm run dev` (server) and `npm run dev:client` (Vite on port 5000)
- **Production Build**: `npm run build` runs esbuild for server with allowlist bundling (reduces cold start) + Vite for client → `dist/public/`
- **Start**: `npm start` runs bundled `dist/index.cjs` with `NODE_ENV=production`
- **Type Check**: `npm run check` (tsc strict mode)
- **DB**: `npm run db:push` syncs schema to PostgreSQL via Drizzle

### Path Aliases (tsconfig.json)
- `@/*` → `client/src/*`
- `@shared/*` → `shared/*`
- `@assets/*` → `attached_assets/*` (research documents)

## Component & Code Patterns

### React Components (Functional + Hooks)
- **Layout**: `Sidebar` uses Wouter for navigation with collapsible state
- **UI Components**: Radix UI + Tailwind (large shadcn-style UI component library in `client/src/components/ui/`)
- **Visualizations**: Custom `NetworkGraph.tsx` (HTML5 Canvas/Recharts) in `client/src/components/viz/`
- **Utils**: `cn()` utility (clsx + tailwind-merge) in `lib/utils.ts`
- **State Management**: React Query (`@tanstack/react-query`) via `lib/queryClient.ts`

### Dashboard Pattern (each page in `client/src/pages/`)
```tsx
// Sidebar + main content wrapper with CardHeader/CardTitle structure
import { Sidebar } from "@/components/layout/Sidebar";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
// Stats state + useEffect intervals for simulated updates
const [stats, setStats] = useState({...});
useEffect(() => setInterval(...), []);
```

### Server Route Pattern
```typescript
// server/routes.ts
export async function registerRoutes(httpServer, app) {
  // Routes with /api prefix
  // Use storage API for CRUD: storage.insertUser(), storage.getUserByUsername()
}
```

### Database Schema
- Drizzle ORM in `shared/schema.ts` with Zod integration (`createInsertSchema`)
- Example: `users` table with UUID PK, unique username, password
- `db:push` command syncs to PostgreSQL

## Critical Development Commands
| Command | Purpose |
|---------|---------|
| `npm run dev` | Start Express server (localhost, auto-reload via tsx watch) |
| `npm run dev:client` | Start Vite dev server (port 5000, HMR enabled) |
| `npm run build` | Bundle both client (Vite) and server (esbuild, CJS) |
| `npm start` | Run production build (`dist/index.cjs`) |
| `npm run check` | TypeScript strict mode validation |
| `npm run db:push` | Sync Drizzle schema to PostgreSQL (requires DATABASE_URL) |

## Key Dependencies
- **Frontend**: React, Vite, Tailwind, Radix UI, Wouter (routing), React Query, chart libraries (Recharts, HTML5 Canvas)
- **Backend**: Express, Drizzle ORM, Zod validation, PostgreSQL driver (`pg`)
- **Build**: esbuild, tsx (TypeScript executor)
- **Visualization**: Lucide Icons, custom Canvas components

## Conventions & Special Notes
1. **Synthetic Data**: Mock data drives dashboards (no live ML inference yet); use `mockData.ts` for examples
2. **Networking**: Server logs all `/api` routes with method, status, duration, response
3. **Environment**: `NODE_ENV` controls Vite dev vs production + Replit-specific plugins
4. **Error Handling**: Express middleware at end of route registration captures errors, returns JSON with `message` field
5. **Assets**: `attached_assets/` holds research prompts/context (ML engineer, SOC analyst personas)

## When Adding Features
- **New Page**: Create in `client/src/pages/`, add route in `App.tsx` router, link in `Sidebar`
- **New API Route**: Add in `server/routes.ts` with `/api` prefix, log via middleware
- **New Database Entity**: Add to `shared/schema.ts`, run `npm run db:push`, create Zod schema with `createInsertSchema()`
- **New UI Component**: Use existing Radix + Tailwind patterns in `client/src/components/ui/`

## File Structure Quick Reference
```
Asset-Analyzer/
├── client/src/
│   ├── pages/          # 8 research dashboards
│   ├── components/
│   │   ├── layout/     # Sidebar, layout wrappers
│   │   ├── ui/         # Radix + Tailwind components
│   │   └── viz/        # Custom visualizations (NetworkGraph, etc)
│   ├── lib/
│   │   ├── mockData.ts      # Synthetic training logs
│   │   ├── advancedMockData.ts # Attack stage predictions
│   │   └── utils.ts         # cn() utility
│   ├── App.tsx         # Router definition
│   └── main.tsx        # React render entry
├── server/
│   ├── index.ts        # Express app, middleware
│   ├── routes.ts       # /api endpoints (add routes here)
│   └── storage.ts      # DB abstraction layer
├── shared/
│   └── schema.ts       # Drizzle ORM schema + Zod validators
├── script/
│   └── build.ts        # esbuild + Vite orchestration
└── vite.config.ts      # Vite + Tailwind + path aliases
```
