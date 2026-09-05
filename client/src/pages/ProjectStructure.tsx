/**
 * Project structure page — documents the real repository layout (not mock content).
 */
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Folder, FileCode, FileText, ChevronRight, ChevronDown } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

type TreeNode = {
  name: string;
  type: "folder" | "file";
  children?: TreeNode[];
};

/** Real project tree used for documentation in the UI. */
const PROJECT_TREE: TreeNode[] = [
  {
    name: "Asset-Analyzer",
    type: "folder",
    children: [
      {
        name: "client/src",
        type: "folder",
        children: [
          { name: "pages/", type: "folder", children: [
            { name: "Dashboard.tsx", type: "file" },
            { name: "AlertCenter.tsx", type: "file" },
            { name: "AttackIntelligence.tsx", type: "file" },
            { name: "Login.tsx", type: "file" },
          ]},
          { name: "lib/api.ts", type: "file" },
          { name: "hooks/useApi.ts", type: "file" },
          { name: "hooks/useWebSocketSync.ts", type: "file" },
        ],
      },
      {
        name: "server",
        type: "folder",
        children: [
          { name: "routes/api.routes.ts", type: "file" },
          { name: "routes/auth.routes.ts", type: "file" },
          { name: "ai-client.ts", type: "file" },
          { name: "websocket.ts", type: "file" },
          { name: "db.ts", type: "file" },
        ],
      },
      {
        name: "ai",
        type: "folder",
        children: [
          { name: "app/main.py", type: "file" },
          { name: "app/services/inference.py", type: "file" },
          { name: "app/services/training.py", type: "file" },
          { name: "app/models/tgnn.py", type: "file" },
          { name: "models/tgnn_model.pt", type: "file" },
          { name: "train_cicids.py", type: "file" },
        ],
      },
      {
        name: "shared",
        type: "folder",
        children: [{ name: "schema.ts", type: "file" }],
      },
      { name: "DataSet/CICIDS2017/", type: "folder" },
      { name: "docker-compose.yml", type: "file" },
      { name: "README.md", type: "file" },
    ],
  },
];

function FileTreeItem({ item, depth = 0 }: { item: TreeNode; depth?: number }) {
  const [isOpen, setIsOpen] = useState(true);

  return (
    <div className="font-mono text-sm">
      <div
        className={cn(
          "flex items-center gap-2 py-1 px-2 hover:bg-white/5 cursor-pointer rounded select-none",
          depth > 0 && "ml-4",
        )}
        onClick={() => item.type === "folder" && setIsOpen(!isOpen)}
      >
        {item.type === "folder" && (
          <span className="text-muted-foreground">
            {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </span>
        )}
        {item.type === "folder" ? (
          <Folder size={16} className="text-blue-400" />
        ) : item.name.endsWith(".py") || item.name.endsWith(".ts") || item.name.endsWith(".tsx") ? (
          <FileCode size={16} className="text-yellow-400" />
        ) : (
          <FileText size={16} className="text-gray-400" />
        )}
        <span className={item.type === "folder" ? "font-bold text-foreground" : "text-muted-foreground"}>
          {item.name}
        </span>
      </div>

      {isOpen && item.children && (
        <div className="pl-4 border-l border-white/5 ml-3">
          {item.children.map((child, i) => (
            <FileTreeItem key={`${child.name}-${i}`} item={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function ProjectStructure() {
  return (
    <main className="flex-1 overflow-auto p-6 space-y-6">
        <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Project Deliverables</h1>
        <p className="text-muted-foreground font-mono text-sm mb-6">
          Real repository layout for the TGNN cyber attack prediction platform.
        </p>

        <Card className="bg-card/30 border-border/50">
          <CardHeader>
            <CardTitle>Source Tree</CardTitle>
          </CardHeader>
          <CardContent>
            {PROJECT_TREE.map((node, i) => (
              <FileTreeItem key={i} item={node} />
            ))}
          </CardContent>
        </Card>

        <Card className="bg-card/30 border-border/50">
          <CardHeader>
            <CardTitle>Key Endpoints</CardTitle>
          </CardHeader>
          <CardContent className="font-mono text-sm space-y-2 text-muted-foreground">
            <div>POST /api/auth/login — JWT authentication</div>
            <div>POST /api/predict/dataset — TGNN inference + PostgreSQL persist</div>
            <div>GET /api/predictions — prediction history</div>
            <div>GET /api/alerts — SOC alerts with MITRE fields</div>
            <div>GET /api/network/topology — live graph</div>
            <div>GET /api/model/info — checkpoint metadata</div>
            <div>WS /ws — live prediction and alert events</div>
          </CardContent>
        </Card>
      </main>
  );
}
