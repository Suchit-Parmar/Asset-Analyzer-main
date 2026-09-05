/**
 * Production API client for GNN-IDS platform.
 * All dashboard data flows through Phase 3 Express/FastAPI endpoints — no simulated values.
 */

const API_BASE = import.meta.env.VITE_API_URL || "";

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: string;
  totpEnabled: boolean;
  permissions: string[];
}

export interface LoginResponse {
  accessToken?: string;
  refreshToken?: string;
  requiresTotp?: boolean;
  email?: string;
  user?: AuthUser;
}

export interface DashboardMetrics {
  alerts: {
    total: number;
    critical: number;
    high: number;
    open: number;
    open24h?: number;
    total24h?: number;
  };
  network: { total: number; compromised: number; suspicious: number; avgRisk: number };
  ai: Record<string, unknown>;
  timestamp: string;
}

export interface Alert {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  attackType: string | null;
  attackStage: string | null;
  mitreTactic: string | null;
  mitreTechnique: string | null;
  sourceIp: string | null;
  targetIp: string | null;
  protocol: string | null;
  predictionId: string | null;
  createdAt: string;
}

export interface NetworkNode {
  id: string;
  ipAddress: string;
  macAddress: string | null;
  hostname: string | null;
  nodeType: string;
  status: string;
  riskScore: number;
  openPorts: number[] | null;
  os: string | null;
  vendor: string | null;
  packets?: number | null;
  bytes?: number | null;
  failedLogins?: number | null;
  connectionCount?: number | null;
  lastSeenAt: string;
  createdAt?: string;
  features?: Record<string, unknown> | null;
}

export interface Topology {
  nodes: Array<{
    id: string;
    label: string;
    ip: string;
    type: string;
    status: string;
    risk: number;
    vendor?: string | null;
    hostname?: string | null;
    websiteName?: string | null;
    packets?: number | null;
    bytes?: number | null;
    connectionCount?: number | null;
    firstSeen?: string | null;
    lastSeen?: string | null;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    protocol: string;
    weight: number;
    packetCount?: number | null;
    timestamp?: string | null;
  }>;
}

export interface LiveDetectionStatus {
  mode?: string;
  status: string;
  running: boolean;
  interface?: string | null;
  window_seconds?: number;
  session_id?: string | null;
  started_at?: string | null;
  last_update?: string | null;
  error?: string | null;
  message?: string;
  model_loaded?: boolean;
  label?: string;
  label_live?: string;
  label_replay?: string;
  stats?: {
    packets?: number;
    flows?: number;
    active_nodes?: number;
    connections?: number;
    windows?: number;
    threats?: number;
    suspicious_nodes?: number;
  };
  prediction?: {
    attack_type?: string;
    confidence?: number | null;
    risk_score?: number | null;
    threat_level?: string;
    is_unknown?: boolean;
    message?: string;
  } | null;
  snapshot?: {
    timestamp?: string;
    node_count?: number;
    edge_count?: number;
    nodes?: Array<Record<string, unknown>>;
    edges?: Array<Record<string, unknown>>;
  } | null;
}

export interface Prediction {
  id: string;
  attackType: string;
  attackStage: string;
  predictedNextStage: string | null;
  threatLevel: string;
  probability: number;
  confidence: number;
  riskScore: number;
  isCompromised: boolean;
  explanation?: Record<string, unknown> | null;
  createdAt: string;
}

export interface ModelInfo {
  model_loaded: boolean;
  device?: string;
  gpu_available?: boolean;
  architecture?: string;
  hidden_dim?: number;
  node_features?: number;
  dataset_id?: string;
  trained_at?: string;
  metrics?: Record<string, number | string>;
  attack_types?: string[];
  attack_stages?: string[];
  model_path?: string;
  model_size_bytes?: number;
  model_size_mb?: number;
  warning?: string;
}

export interface PredictResult extends Prediction {
  alertId?: string | null;
  stored?: boolean;
  mitre_tactic?: string;
  mitre_technique?: string;
  all_probabilities?: Record<string, number>;
  stage_probabilities?: Record<string, number>;
  model?: Record<string, unknown>;
  graph?: Record<string, unknown>;
  dataset_id?: string;
}

export interface TrainingRun {
  id: string;
  architecture: string;
  status: string;
  epochs: number;
  currentEpoch: number;
  trainLoss: number | null;
  valLoss: number | null;
  trainAccuracy: number | null;
  valAccuracy: number | null;
  metrics: Record<string, unknown>;
  gpuUtilization: number | null;
  createdAt: string;
}

export interface AttackStageEntry {
  stage: string;
  stageKey: string;
  probability: number;
  entities: string[];
  description: string;
}

export interface AttackStageSummary {
  attackStages: AttackStageEntry[];
  edges: Array<{ source: string; target: string; type: string; weight: number; timestamp: string }>;
  stats: {
    totalPredictions: number;
    maliciousShare: number;
    avgConfidence: number;
    leadStage: AttackStageEntry | null;
    stageCount: number;
  };
  timestamp: string;
}

export interface ExplainabilityResult {
  node_id: string;
  target_node?: Record<string, unknown>;
  node_importance: Array<{ node_index?: number; ip?: string; label?: string; importance: number; entity?: string }>;
  edge_importance: Array<{ edge_index?: number; source?: string; target?: string; importance: number; protocol?: string }>;
  reasoning: string;
  reasoning_tree?: Array<{
    id: string;
    label: string;
    detail?: string;
    children?: ExplainabilityResult["reasoning_tree"];
  }>;
  graph_heatmap?: {
    nodes: Array<{ id: string; ip?: string; label?: string; importance: number; intensity: number }>;
    edges: Array<{ source?: string; target?: string; protocol?: string; importance: number; intensity: number }>;
    max_node_importance?: number;
    max_edge_importance?: number;
  };
  integrated_gradients?: Array<{ feature: string; importance: number; method?: string }>;
  shap_values?: Array<{ feature: string; shap_value: number; method?: string }>;
  attention_weights?: Array<{ head?: number; weight: number }>;
  graphSnapshot?: Record<string, unknown>;
  targetNodeId?: string;
  fallback?: boolean;
}

export interface ApprovalRecord {
  id: string;
  candidate_id: string;
  approved_at: string;
  approved_by?: string | null;
  comparison_recommendation?: string;
  active_dataset?: string;
  metrics_delta?: Record<string, unknown>;
}

export interface RiskScoreEntry {
  id: string;
  entityType: string;
  entityId: string;
  entityName: string;
  nodeRisk: number | null;
  subnetRisk: number | null;
  departmentRisk?: number | null;
  organizationRisk: number | null;
  propagationRisk: number | null;
  businessImpact: number | null;
  computedAt: string;
}

export interface MetricsResponse {
  model_loaded?: boolean;
  architecture?: string;
  metrics?: Record<string, unknown>;
  trained_at?: string;
  dataset_id?: string;
  graph_strategy?: string;
  headline?: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1?: number;
    macro_f1?: number;
    weighted_f1?: number;
    roc_auc?: number;
    train_loss?: number;
    val_loss?: number;
    best_epoch?: number;
  };
  macro?: { precision?: number; recall?: number; f1?: number };
  weighted?: { precision?: number; recall?: number; f1?: number };
  per_class?: Record<string, { precision?: number; recall?: number; f1?: number; support?: number }>;
  confusion_matrix?: number[][];
  class_labels?: string[];
  class_distribution?: Array<{ class: string; count: number }>;
  roc_curves?: Record<string, Array<{ fpr: number; tpr: number }>>;
  pr_curves?: Record<string, Array<{ recall: number; precision: number }>>;
  learning_curve?: Array<Record<string, number | undefined>>;
  training_time_sec?: number;
  inference_time_ms?: number;
  model_size_mb?: number;
  model_size_bytes?: number;
}

export interface StudioConfig {
  dataset_id?: string;
  architecture?: string;
  graph_strategy?: string;
  graph_params?: Record<string, unknown>;
  feature_set?: Record<string, boolean>;
  hyperparameters?: Record<string, number>;
}

export interface RegistryModel {
  id: string;
  name?: string;
  dataset_id?: string;
  architecture?: string;
  graph_strategy?: string;
  graph_params?: Record<string, unknown>;
  feature_set?: Record<string, unknown>;
  trained_at?: string;
  is_active?: boolean;
  size_bytes?: number;
  file?: string;
  metrics?: {
    accuracy?: number;
    f1?: number;
    test_accuracy?: number;
    test_f1?: number;
    macro_f1?: number;
    roc_auc?: number;
    best_epoch?: number;
    training_time_sec?: number;
    inference_time_ms?: number;
    graph_stats?: Record<string, number>;
  };
  error?: string;
}

export interface ModelRegistryResponse {
  models: RegistryModel[];
  active: { dataset_id?: string; trained_at?: string };
  model_dir: string;
}

// --- Phase 12: Continual Learning ---

export interface DatasetVersion {
  version: string;
  version_number: number;
  name: string;
  display_name?: string;
  source?: string;
  created_at?: string;
  rows?: number;
  columns?: number;
  hash?: string;
  classes?: string[];
  attack_distribution?: Record<string, number>;
  quality_score?: number;
  quality_passed?: boolean;
  note?: string | null;
}

export interface DatasetVersionsResponse {
  datasets: Array<{
    name: string;
    display_name?: string;
    latest_version?: string;
    version_count: number;
    versions: DatasetVersion[];
  }>;
  root: string;
}

export interface DriftReport {
  name?: string;
  computed_at?: string;
  severity: "none" | "moderate" | "significant" | string;
  drift_types: string[];
  recommend_retraining: boolean;
  avg_psi: number;
  max_psi: number;
  drifted_features: string[];
  feature_psi: Record<string, number>;
  label_drift: number;
  accuracy_drop?: number | null;
  summary: string;
}

export interface ExperimentRecord {
  id: string;
  recorded_at?: string;
  dataset_id?: string;
  architecture?: string;
  mode?: string;
  model_slug?: string;
  activated?: boolean;
  epochs?: number;
  graph_strategy?: string;
  git_commit?: string | null;
  metrics?: Record<string, unknown>;
  training_time_sec?: number;
  checkpoint?: string;
}

export interface ReviewSample {
  id: string;
  captured_at?: string;
  status: string;
  confidence: number;
  predicted_attack_type?: string;
  threat_level?: string;
  reason?: string;
  true_label?: string | null;
  features?: Record<string, number>;
  graph?: Record<string, number>;
}

export interface ReviewQueueResponse {
  samples: ReviewSample[];
  stats: {
    total: number;
    pending: number;
    labeled: number;
    approved: number;
    rejected: number;
    capacity: number;
  };
}

export interface ModelComparison {
  candidate_id: string;
  active_id?: string | null;
  comparison: {
    rows: Array<{ metric: string; active: unknown; candidate: unknown; delta: number | null; better: string | null }>;
    candidate_better: boolean;
    recommendation: string;
    reason: string;
    note: string;
  };
}

export interface KnowledgeBase {
  known_attacks: Array<{ name: string; mitre_tactic: string; mitre_technique: string; threat_level: string }>;
  historical_attacks: Array<{ name: string; count: number }>;
  unknown_attacks: Array<{ name: string; count: number }>;
  emerging_patterns: Array<{ name: string; new_share: number; previous_share: number; delta: number }>;
  review_queue: Record<string, number>;
  summary: string;
}

export interface SocResponseRequest {
  attack_type: string;
  attack_stage?: string | null;
  confidence?: number;
  threat_level?: string;
  risk_score?: number;
  mitre_tactic?: string | null;
  mitre_technique?: string | null;
  source_ip?: string | null;
  target_ip?: string | null;
  protocol?: string | null;
  port?: number | string | null;
}

export interface SocResponse {
  attack_type: string;
  attack_stage?: string | null;
  mitre: { tactic: string; technique: string; technique_url: string | null };
  kill_chain_stage: string;
  severity: string;
  confidence: number;
  risk_score: number;
  recommended_action: string;
  recommended_response: string[];
  firewall_rule: { linux: string; windows: string };
  isolation_command: string;
  detection_rules: { sigma: string; yara: string; suricata: string; snort: string };
  analyst_notes: string;
  risk_summary: string;
}

export interface TrainingHistoryResponse {
  history: ExperimentRecord[];
  accuracy_trend: Array<{
    id?: string;
    recorded_at?: string;
    dataset_id?: string;
    architecture?: string;
    mode?: string;
    accuracy?: number;
    f1?: number;
    macro_f1?: number;
    roc_auc?: number;
  }>;
}

class ApiClient {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  constructor() {
    this.accessToken = localStorage.getItem("gnn-ids-access-token");
    this.refreshToken = localStorage.getItem("gnn-ids-refresh-token");
  }

  setTokens(access: string, refresh: string) {
    this.accessToken = access;
    this.refreshToken = refresh;
    localStorage.setItem("gnn-ids-access-token", access);
    localStorage.setItem("gnn-ids-refresh-token", refresh);
    localStorage.setItem("gnn-ids-auth", "true");
    localStorage.removeItem("gnn-ids-user");
  }

  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem("gnn-ids-access-token");
    localStorage.removeItem("gnn-ids-refresh-token");
    localStorage.removeItem("gnn-ids-auth");
    localStorage.removeItem("gnn-ids-user");
  }

  getAccessToken() {
    return this.accessToken;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };

    if (this.accessToken) {
      headers.Authorization = `Bearer ${this.accessToken}`;
    }

    let response = await fetch(`${API_BASE}${path}`, { ...options, headers });

    if (response.status === 401 && this.refreshToken) {
      const refreshed = await this.tryRefresh();
      if (refreshed) {
        headers.Authorization = `Bearer ${this.accessToken}`;
        response = await fetch(`${API_BASE}${path}`, { ...options, headers });
      }
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: "Request failed" }));
      const message = error.error || error.detail || error.message || `HTTP ${response.status}`;
      if (response.status === 429) {
        throw new Error(`${message}. Wait a minute and try again.`);
      }
      throw new Error(message);
    }

    return response.json();
  }

  private async tryRefresh(): Promise<boolean> {
    try {
      const res = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: this.refreshToken }),
      });
      if (!res.ok) return false;
      const data = await res.json();
      this.accessToken = data.accessToken;
      localStorage.setItem("gnn-ids-access-token", data.accessToken);
      return true;
    } catch {
      this.clearTokens();
      return false;
    }
  }

  async login(email: string, password: string, totpCode?: string): Promise<LoginResponse> {
    const data = await this.request<LoginResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password, totpCode }),
    });
    if (data.accessToken && data.refreshToken) {
      this.setTokens(data.accessToken, data.refreshToken);
    }
    return data;
  }

  async register(name: string, email: string, password: string) {
    return this.request("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ name, email, password }),
    });
  }

  async logout() {
    try {
      await this.request("/api/auth/logout", {
        method: "POST",
        body: JSON.stringify({ refreshToken: this.refreshToken }),
      });
    } finally {
      this.clearTokens();
    }
  }

  async getMe(): Promise<AuthUser> {
    return this.request("/api/auth/me");
  }

  async setupTotp() {
    return this.request<{ qrCode: string; secret: string }>("/api/auth/totp/setup", { method: "POST" });
  }

  async verifyTotp(code: string) {
    return this.request("/api/auth/totp/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  async getDashboardMetrics(): Promise<DashboardMetrics> {
    return this.request("/api/dashboard/metrics");
  }

  async getAlerts(params?: { severity?: string; status?: string; limit?: number }) {
    const qs = new URLSearchParams();
    if (params?.severity) qs.set("severity", params.severity);
    if (params?.status) qs.set("status", params.status);
    if (params?.limit) qs.set("limit", String(params.limit));
    return this.request<{ alerts: Alert[]; count: number }>(`/api/alerts?${qs}`);
  }

  async updateAlert(id: string, status: string) {
    return this.request(`/api/alerts/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    });
  }

  async getNetworkNodes(params?: { status?: string; limit?: number }) {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.limit) qs.set("limit", String(params.limit ?? 100));
    return this.request<{ nodes: NetworkNode[]; count: number }>(`/api/network/nodes?${qs}`);
  }

  async getTopology(): Promise<Topology> {
    return this.request("/api/network/topology");
  }

  async addWebsite(body: { url: string }) {
    return this.request<{ node: NetworkNode; websiteName?: string; note: string }>("/api/network/websites", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  async getLiveInterfaces() {
    return this.request<{ interfaces: Array<{
      name: string;
      display_name?: string;
      ipv4?: string | null;
      is_up?: boolean;
      speed_mbps?: number | null;
    }> }>("/api/live/interfaces");
  }

  async startLive(body: { interface: string; windowSeconds?: number }) {
    return this.request<LiveDetectionStatus>("/api/live/start", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  async stopLive() {
    return this.request<LiveDetectionStatus>("/api/live/stop", { method: "POST" });
  }

  async getLiveStatus() {
    return this.request<LiveDetectionStatus>("/api/live/status");
  }

  async getLiveHistory() {
    return this.request<{ windows: Array<Record<string, unknown>>; count: number }>("/api/live/history");
  }

  async getPredictions(limit = 50) {
    return this.request<{ predictions: Prediction[] }>(`/api/predictions?limit=${limit}`);
  }

  async getAttackStages() {
    return this.request<AttackStageSummary>("/api/attack-stage");
  }

  async getLatestExplanation() {
    return this.request<ExplainabilityResult>("/api/explain/latest");
  }

  async predict(features: Record<string, unknown>, graphSnapshot?: Record<string, unknown>) {
    return this.request<PredictResult>("/api/predict", {
      method: "POST",
      body: JSON.stringify({ features, graphSnapshot }),
    });
  }

  async predictBatch(records: Record<string, unknown>[]) {
    return this.request<{ predictions: PredictResult[]; count: number }>("/api/predict/batch", {
      method: "POST",
      body: JSON.stringify({ records }),
    });
  }

  async predictDataset(datasetId = "cicids2017", windowSeconds = 30, maxRows = 3000) {
    return this.request<PredictResult>("/api/predict/dataset", {
      method: "POST",
      body: JSON.stringify({ datasetId, windowSeconds, maxRows }),
    });
  }

  async getModelInfo() {
    return this.request<ModelInfo>("/api/model/info");
  }

  async reloadModel() {
    return this.request<ModelInfo>("/api/model/reload", { method: "POST" });
  }

  async getModels() {
    return this.request<{ models: Array<Record<string, unknown>> }>("/api/models");
  }

  async getModelRegistry() {
    return this.request<ModelRegistryResponse>("/api/models/registry");
  }

  async activateModel(id: string) {
    return this.request<Record<string, unknown>>(`/api/models/${encodeURIComponent(id)}/activate`, {
      method: "POST",
    });
  }

  async deleteModel(id: string) {
    return this.request<Record<string, unknown>>(`/api/models/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
  }

  async exportModelMetadata(id: string) {
    return this.request<Record<string, unknown>>(`/api/models/${encodeURIComponent(id)}/export`);
  }

  async explain(nodeId: string, graphSnapshot: Record<string, unknown>) {
    return this.request("/api/explain", {
      method: "POST",
      body: JSON.stringify({ nodeId, graphSnapshot }),
    });
  }

  async getRiskScores(entityType?: string) {
    const qs = entityType ? `?entity_type=${entityType}` : "";
    return this.request<{ scores: RiskScoreEntry[] }>(`/api/risk/scores${qs}`);
  }

  async computeRisk(entityType: string, entityId: string, graphSnapshot: Record<string, unknown>) {
    return this.request("/api/risk/compute", {
      method: "POST",
      body: JSON.stringify({ entityType, entityId, graphSnapshot }),
    });
  }

  async getMetrics(modelId?: string) {
    const qs = modelId ? `?model_id=${modelId}` : "";
    return this.request<MetricsResponse>(`/api/metrics${qs}`);
  }

  async getNetworkEdges(limit = 200) {
    return this.request<{
      edges: Array<{
        id: string;
        sourceNodeId: string;
        targetNodeId: string;
        protocol: string;
        weight: number;
        timestamp: string;
        packetCount: number | null;
      }>;
      count: number;
    }>(`/api/network/edges?limit=${limit}`);
  }

  async getTrainingRuns() {
    return this.request<{ runs: TrainingRun[] }>("/api/training/runs");
  }

  async startTraining(params: {
    datasetId: string;
    architecture: string;
    hyperparameters?: Record<string, unknown>;
    epochs?: number;
    graphStrategy?: string;
    graphParams?: Record<string, unknown>;
    featureSet?: Record<string, boolean>;
  }) {
    return this.request("/api/training/start", {
      method: "POST",
      body: JSON.stringify({
        datasetId: params.datasetId,
        architecture: params.architecture,
        hyperparameters: params.hyperparameters ?? {},
        epochs: params.epochs ?? 50,
        graphStrategy: params.graphStrategy,
        graphParams: params.graphParams ?? {},
        featureSet: params.featureSet,
      }),
    });
  }

  async getGraphStrategies() {
    return this.request<{ strategies: string[] }>("/api/graph/strategies");
  }

  async getStudioConfig() {
    return this.request<StudioConfig>("/api/config");
  }

  async saveStudioConfig(config: StudioConfig) {
    return this.request<StudioConfig>("/api/config", {
      method: "POST",
      body: JSON.stringify({ config }),
    });
  }

  async getTrainingRun(id: string) {
    return this.request(`/api/training/runs/${id}`);
  }

  // --- Phase 12: Continual Learning ---

  async getDatasetVersions(name?: string) {
    const qs = name ? `?name=${encodeURIComponent(name)}` : "";
    return this.request<DatasetVersionsResponse>(`/api/datasets/versions${qs}`);
  }

  async registerDataset(body: { name?: string; datasetId: string; source?: string; maxRows?: number }) {
    return this.request<Record<string, unknown>>("/api/datasets/register", {
      method: "POST",
      body: JSON.stringify({
        name: body.name,
        dataset_id: body.datasetId,
        source: body.source ?? "loader",
        max_rows: body.maxRows ?? 20000,
      }),
    });
  }

  async getDrift() {
    return this.request<{ reports: DriftReport[] }>("/api/drift");
  }

  async computeDrift(body: { name?: string; datasetId: string; maxRows?: number }) {
    return this.request<DriftReport & { available?: boolean; message?: string }>("/api/drift", {
      method: "POST",
      body: JSON.stringify({ name: body.name, dataset_id: body.datasetId, max_rows: body.maxRows ?? 20000 }),
    });
  }

  async getExperiments(datasetId?: string) {
    const qs = datasetId ? `?dataset_id=${encodeURIComponent(datasetId)}` : "";
    return this.request<{ experiments: ExperimentRecord[] }>(`/api/experiments${qs}`);
  }

  async getTrainingHistory(datasetId?: string) {
    const qs = datasetId ? `?dataset_id=${encodeURIComponent(datasetId)}` : "";
    return this.request<TrainingHistoryResponse>(`/api/training/history${qs}`);
  }

  async getApprovalHistory(limit = 100) {
    return this.request<{ approvals: ApprovalRecord[]; count: number }>(`/api/approvals?limit=${limit}`);
  }

  async retrainCandidate(body: {
    datasetId: string;
    architecture?: string;
    epochs?: number;
    mode?: string;
    graphStrategy?: string;
    graphParams?: Record<string, unknown>;
    hyperparameters?: Record<string, unknown>;
    useReplay?: boolean;
    replayRatio?: number;
    includeReviewSamples?: boolean;
  }) {
    return this.request<{ run_id: string; candidate_id: string; mode: string; message: string; replay_rows?: number }>("/api/retrain", {
      method: "POST",
      body: JSON.stringify({
        dataset_id: body.datasetId,
        architecture: body.architecture ?? "gat",
        epochs: body.epochs ?? 30,
        mode: body.mode ?? "full",
        graph_strategy: body.graphStrategy,
        graph_params: body.graphParams ?? {},
        hyperparameters: body.hyperparameters ?? {},
        use_replay: body.useReplay ?? false,
        replay_ratio: body.replayRatio ?? 0.15,
        include_review_samples: body.includeReviewSamples ?? false,
      }),
    });
  }

  async rollbackModel() {
    return this.request<Record<string, unknown>>("/api/rollback", { method: "POST" });
  }

  async getRollbackInfo() {
    return this.request<{ available: boolean; previous_model_id?: string; message?: string }>("/api/rollback/info");
  }

  async compareCandidate(candidateId: string) {
    return this.request<ModelComparison>("/api/compare", {
      method: "POST",
      body: JSON.stringify({ candidateId }),
    });
  }

  async approveCandidate(candidateId: string) {
    return this.request<Record<string, unknown>>("/api/approve-model", {
      method: "POST",
      body: JSON.stringify({ candidateId }),
    });
  }

  async getReviewQueue(status?: string) {
    const qs = status ? `?status=${encodeURIComponent(status)}` : "";
    return this.request<ReviewQueueResponse>(`/api/review${qs}`);
  }

  async relabelReview(id: string, label: string) {
    return this.request<Record<string, unknown>>(`/api/review/${encodeURIComponent(id)}/relabel`, {
      method: "POST",
      body: JSON.stringify({ label }),
    });
  }

  async approveReview(id: string) {
    return this.request<Record<string, unknown>>(`/api/review/${encodeURIComponent(id)}/approve`, {
      method: "POST",
    });
  }

  async getKnowledgeBase() {
    return this.request<KnowledgeBase>("/api/knowledge-base");
  }

  async getSocResponse(body: SocResponseRequest) {
    return this.request<SocResponse>("/api/soc/response", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  reportDownloadUrl(format: "csv" | "html" | "json", modelId?: string) {
    const qs = new URLSearchParams({ format });
    if (modelId) qs.set("model_id", modelId);
    return `${API_BASE}/api/reports/evaluation?${qs}`;
  }

  /** Authenticated report download (bare <a href> fails with 401). */
  async downloadReport(format: "csv" | "html" | "json", modelId?: string): Promise<void> {
    const url = this.reportDownloadUrl(format, modelId);
    const headers: Record<string, string> = {};
    if (this.accessToken) headers.Authorization = `Bearer ${this.accessToken}`;

    let response = await fetch(url, { headers });
    if (response.status === 401 && this.refreshToken) {
      const refreshed = await this.tryRefresh();
      if (refreshed) {
        headers.Authorization = `Bearer ${this.accessToken}`;
        response = await fetch(url, { headers });
      }
    }
    if (!response.ok) {
      const err = await response.json().catch(() => ({ error: "Report download failed" }));
      throw new Error(err.error || err.detail || `HTTP ${response.status}`);
    }

    const blob = await response.blob();
    const objectUrl = URL.createObjectURL(blob);
    if (format === "html") {
      window.open(objectUrl, "_blank", "noopener,noreferrer");
      // Revoke after the new tab has a chance to load.
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
      return;
    }

    const a = document.createElement("a");
    a.href = objectUrl;
    a.download = `evaluation-report.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(objectUrl);
  }

  async getDatasets() {
    return this.request("/api/datasets");
  }

  async uploadDataset(file: File, source: string, name: string) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("source", source);
    formData.append("name", name);

    const headers: Record<string, string> = {};
    if (this.accessToken) headers.Authorization = `Bearer ${this.accessToken}`;

    const response = await fetch(`${API_BASE}/api/datasets/upload`, {
      method: "POST",
      headers,
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: "Upload failed" }));
      throw new Error(error.error || "Upload failed");
    }
    return response.json();
  }

  async buildGraph(datasetId: string, windowSeconds = 30) {
    return this.request("/api/graph/build", {
      method: "POST",
      body: JSON.stringify({ datasetId, windowSeconds }),
    });
  }

  async getHealth() {
    return this.request<{
      status: string;
      ai: Record<string, unknown>;
      api?: {
        cpu_count?: number;
        load_avg?: number[];
        memory_total_bytes?: number;
        memory_used_bytes?: number;
        memory_percent?: number;
        process_rss_bytes?: number;
        uptime_sec?: number;
        platform?: string;
      };
      timestamp: string;
    }>("/api/health");
  }

  async getAdminHealth() {
    return this.request<{
      api: Record<string, unknown>;
      ai: Record<string, unknown>;
      timestamp: string;
    }>("/api/admin/health");
  }

  async getAdminAuditLogs(limit = 100) {
    return this.request<{ logs: Array<Record<string, unknown>>; count: number }>(
      `/api/admin/audit-logs?limit=${limit}`,
    );
  }

  async getAdminApiLogs(limit = 100, level?: string) {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (level) qs.set("level", level);
    return this.request<{ logs: Array<Record<string, unknown>>; count: number }>(
      `/api/admin/api-logs?${qs}`,
    );
  }

  async getAdminTrainingLogs(limit = 50) {
    return this.request<{ runs: Array<Record<string, unknown>>; count: number }>(
      `/api/admin/training-logs?limit=${limit}`,
    );
  }

  async getAdminPredictionLogs(limit = 50) {
    return this.request<{ predictions: Array<Record<string, unknown>>; count: number }>(
      `/api/admin/prediction-logs?limit=${limit}`,
    );
  }

  async getAdminSystemLogs(limit = 100) {
    return this.request<{ logs: Array<Record<string, unknown>>; count: number }>(
      `/api/admin/system-logs?limit=${limit}`,
    );
  }

  createWebSocket(
    onMessage: (data: unknown) => void,
    handlers?: { onOpen?: () => void; onClose?: () => void; onError?: () => void },
  ): WebSocket | null {
    if (!this.accessToken) return null;
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsHost = API_BASE ? new URL(API_BASE).host : window.location.host;
    const ws = new WebSocket(`${wsProtocol}//${wsHost}/ws?token=${this.accessToken}`);

    ws.onopen = () => handlers?.onOpen?.();
    ws.onclose = () => handlers?.onClose?.();
    ws.onerror = () => handlers?.onError?.();
    ws.onmessage = (event) => {
      try {
        onMessage(JSON.parse(event.data));
      } catch {
        // ignore malformed frames
      }
    };

    return ws;
  }
}

export const api = new ApiClient();
