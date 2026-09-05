/**
 * HTTP client for the FastAPI TGNN service.
 * Production note: keep path/field names aligned with ai/app/main.py.
 */
const AI_SERVICE_URL = process.env.AI_SERVICE_URL || "http://localhost:8000";

export class AIServiceClient {
  private baseUrl: string;

  constructor(baseUrl = AI_SERVICE_URL) {
    this.baseUrl = baseUrl;
  }

  async health(): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/health`);
    if (!res.ok) throw new Error("AI service unavailable");
    return res.json();
  }

  async adminSystem(): Promise<Record<string, unknown>> {
    return this.getJson("/api/v1/admin/system", "AI system metrics unavailable");
  }

  async modelInfo(): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/api/v1/model/info`);
    if (!res.ok) throw new Error("Model info unavailable");
    return res.json();
  }

  async reloadModel(): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/api/v1/model/reload`, { method: "POST" });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Model reload failed" }));
      throw new Error(err.detail || "Model reload failed");
    }
    return res.json();
  }

  async listRegistryModels(): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/api/v1/models`);
    if (!res.ok) throw new Error("Model registry unavailable");
    return res.json();
  }

  async getModelMetadata(modelId: string): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/api/v1/models/${encodeURIComponent(modelId)}/metadata`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Model metadata unavailable" }));
      throw new Error(typeof err.detail === "string" ? err.detail : "Model metadata unavailable");
    }
    return res.json();
  }

  async activateModel(modelId: string): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/api/v1/models/${encodeURIComponent(modelId)}/activate`, {
      method: "POST",
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Activate model failed" }));
      throw new Error(typeof err.detail === "string" ? err.detail : "Activate model failed");
    }
    return res.json();
  }

  async deleteRegistryModel(modelId: string): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/api/v1/models/${encodeURIComponent(modelId)}`, {
      method: "DELETE",
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Delete model failed" }));
      throw new Error(typeof err.detail === "string" ? err.detail : "Delete model failed");
    }
    return res.json();
  }

  async predict(features: Record<string, unknown>, graphSnapshot?: Record<string, unknown>) {
    const res = await fetch(`${this.baseUrl}/api/v1/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ features, graph_snapshot: graphSnapshot }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Prediction failed" }));
      throw new Error(typeof err.detail === "string" ? err.detail : "Prediction failed");
    }
    return res.json();
  }

  async predictBatch(records: Record<string, unknown>[]) {
    const res = await fetch(`${this.baseUrl}/api/v1/predict/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ records }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Batch prediction failed" }));
      throw new Error(typeof err.detail === "string" ? err.detail : "Batch prediction failed");
    }
    return res.json();
  }

  async predictFromDataset(
    datasetId: string,
    windowSeconds = 30,
    maxRows = 5000,
    graphStrategy?: string,
    graphParams?: Record<string, unknown>,
  ) {
    const res = await fetch(`${this.baseUrl}/api/v1/predict/from-dataset`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        dataset_id: datasetId,
        window_seconds: windowSeconds,
        max_rows: maxRows,
        graph_strategy: graphStrategy,
        graph_params: graphParams ?? {},
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Dataset prediction failed" }));
      throw new Error(typeof err.detail === "string" ? err.detail : "Dataset prediction failed");
    }
    return res.json();
  }

  async explain(nodeId: string, graphSnapshot: Record<string, unknown>) {
    const res = await fetch(`${this.baseUrl}/api/v1/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ node_id: nodeId, graph_snapshot: graphSnapshot }),
    });
    if (!res.ok) throw new Error("Explainability request failed");
    return res.json();
  }

  async startTraining(params: Record<string, unknown>) {
    const res = await fetch(`${this.baseUrl}/api/v1/train`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
    });
    if (!res.ok) throw new Error("Training start failed");
    return res.json();
  }

  async getTrainingStatus(runId: string) {
    const res = await fetch(`${this.baseUrl}/api/v1/train/${runId}`);
    // AI keeps run state in memory; 404 means the run is unknown (service restarted).
    if (res.status === 404) return null;
    if (!res.ok) throw new Error("Training status unavailable");
    return res.json();
  }

  async ingestDataset(formData: FormData) {
    const res = await fetch(`${this.baseUrl}/api/v1/datasets/upload`, {
      method: "POST",
      body: formData,
    });
    if (!res.ok) throw new Error("Dataset upload failed");
    return res.json();
  }

  async buildGraph(
    datasetId: string,
    windowSeconds: number,
    graphStrategy?: string,
    graphParams?: Record<string, unknown>,
  ) {
    const res = await fetch(`${this.baseUrl}/api/v1/graph/build`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        dataset_id: datasetId,
        window_seconds: windowSeconds,
        graph_strategy: graphStrategy,
        graph_params: graphParams ?? {},
      }),
    });
    if (!res.ok) throw new Error("Graph build failed");
    return res.json();
  }

  async listGraphStrategies(): Promise<{ strategies: string[] }> {
    const res = await fetch(`${this.baseUrl}/api/v1/graph/strategies`);
    if (!res.ok) throw new Error("Graph strategies unavailable");
    return res.json();
  }

  async getStudioConfig(): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/api/v1/config`);
    if (!res.ok) throw new Error("Studio config unavailable");
    return res.json();
  }

  async saveStudioConfig(config: Record<string, unknown>): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/api/v1/config`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ config }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Save config failed" }));
      throw new Error(typeof err.detail === "string" ? err.detail : "Save config failed");
    }
    return res.json();
  }

  // --- Phase 12: Continual Learning -------------------------------------

  private async getJson(path: string, errorMsg: string): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}${path}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: errorMsg }));
      throw new Error(typeof err.detail === "string" ? err.detail : errorMsg);
    }
    return res.json();
  }

  private async postJson(
    path: string,
    body: Record<string, unknown>,
    errorMsg: string,
  ): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: errorMsg }));
      const detail = typeof err.detail === "string" ? err.detail : errorMsg;
      const error = new Error(detail) as Error & { status?: number };
      error.status = res.status;
      throw error;
    }
    return res.json();
  }

  listDatasetVersions(name?: string) {
    const qs = name ? `?name=${encodeURIComponent(name)}` : "";
    return this.getJson(`/api/v1/datasets${qs}`, "Dataset versions unavailable");
  }

  datasetHistory() {
    return this.getJson(`/api/v1/datasets/history`, "Dataset history unavailable");
  }

  registerDataset(body: Record<string, unknown>) {
    return this.postJson(`/api/v1/datasets`, body, "Dataset registration failed");
  }

  getDrift() {
    return this.getJson(`/api/v1/drift`, "Drift reports unavailable");
  }

  computeDrift(body: Record<string, unknown>) {
    return this.postJson(`/api/v1/drift`, body, "Drift computation failed");
  }

  listExperiments(datasetId?: string) {
    const qs = datasetId ? `?dataset_id=${encodeURIComponent(datasetId)}` : "";
    return this.getJson(`/api/v1/experiments${qs}`, "Experiments unavailable");
  }

  trainingHistory(datasetId?: string) {
    const qs = datasetId ? `?dataset_id=${encodeURIComponent(datasetId)}` : "";
    return this.getJson(`/api/v1/training/history${qs}`, "Training history unavailable");
  }

  approvalHistory(limit = 100) {
    return this.getJson(`/api/v1/approvals?limit=${limit}`, "Approval history unavailable");
  }

  retrainCandidate(body: Record<string, unknown>) {
    return this.postJson(`/api/v1/retrain`, body, "Retrain failed");
  }

  compareModels(candidateId: string) {
    return this.postJson(`/api/v1/compare`, { candidate_id: candidateId }, "Compare failed");
  }

  approveModel(candidateId: string) {
    return this.postJson(`/api/v1/approve-model`, { candidate_id: candidateId }, "Approve model failed");
  }

  rollbackModel() {
    return this.postJson(`/api/v1/rollback`, {}, "Rollback failed");
  }

  rollbackInfo() {
    return this.getJson(`/api/v1/rollback/info`, "Rollback info unavailable");
  }

  replayStats() {
    return this.getJson(`/api/v1/replay/stats`, "Replay stats unavailable");
  }

  listReview(status?: string) {
    const qs = status ? `?status=${encodeURIComponent(status)}` : "";
    return this.getJson(`/api/v1/review${qs}`, "Review queue unavailable");
  }

  relabelReview(sampleId: string, label: string) {
    return this.postJson(
      `/api/v1/review/${encodeURIComponent(sampleId)}/relabel`,
      { label },
      "Relabel failed",
    );
  }

  approveReview(sampleId: string) {
    return this.postJson(
      `/api/v1/review/${encodeURIComponent(sampleId)}/approve`,
      {},
      "Approve sample failed",
    );
  }

  knowledgeBase() {
    return this.getJson(`/api/v1/knowledge-base`, "Knowledge base unavailable");
  }

  socResponse(body: Record<string, unknown>) {
    return this.postJson(`/api/v1/soc/response`, body, "SOC response generation failed");
  }

  async getReport(format = "json", modelId?: string): Promise<{ content: string; contentType: string }> {
    const qs = new URLSearchParams({ format });
    if (modelId) qs.set("model_id", modelId);
    const res = await fetch(`${this.baseUrl}/api/v1/reports?${qs}`);
    if (!res.ok) throw new Error("Report generation failed");
    const contentType = res.headers.get("content-type") || "application/json";
    return { content: await res.text(), contentType };
  }

  async computeRisk(entityType: string, entityId: string, graphSnapshot: Record<string, unknown>) {
    const res = await fetch(`${this.baseUrl}/api/v1/risk/compute`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ entity_type: entityType, entity_id: entityId, graph_snapshot: graphSnapshot }),
    });
    if (!res.ok) throw new Error("Risk computation failed");
    return res.json();
  }

  async liveInterfaces() {
    return this.getJson("/api/v1/live/interfaces", "Live interfaces unavailable");
  }

  async liveStart(interfaceName: string, windowSeconds = 5) {
    return this.postJson(
      "/api/v1/live/start",
      { interface: interfaceName, window_seconds: windowSeconds },
      "Live start failed",
    );
  }

  async liveStop() {
    return this.postJson("/api/v1/live/stop", {}, "Live stop failed");
  }

  async liveStatus() {
    return this.getJson("/api/v1/live/status", "Live status unavailable");
  }

  async liveHistory() {
    return this.getJson("/api/v1/live/history", "Live history unavailable");
  }

  async getMetrics(modelId?: string) {
    const url = modelId
      ? `${this.baseUrl}/api/v1/metrics?model_id=${modelId}`
      : `${this.baseUrl}/api/v1/metrics`;
    const res = await fetch(url);
    if (!res.ok) throw new Error("Metrics unavailable");
    return res.json();
  }
}

export const aiService = new AIServiceClient();
