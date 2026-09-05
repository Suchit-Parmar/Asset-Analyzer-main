import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";

export function useDashboardMetrics() {
  return useQuery({
    queryKey: ["dashboard", "metrics"],
    queryFn: () => api.getDashboardMetrics(),
    refetchInterval: 5000,
  });
}

export function useAlerts(severity?: string, status?: string) {
  return useQuery({
    queryKey: ["alerts", severity, status],
    queryFn: () => api.getAlerts({ severity, status, limit: 50 }),
    refetchInterval: 3000,
  });
}

export function useNetworkNodes(status?: string, enabled = true) {
  return useQuery({
    queryKey: ["network", "nodes", status],
    queryFn: () => api.getNetworkNodes({ status, limit: 100 }),
    refetchInterval: enabled ? 5000 : false,
    enabled,
  });
}

export function useTopology() {
  return useQuery({
    queryKey: ["network", "topology"],
    queryFn: () => api.getTopology(),
    refetchInterval: 5000,
  });
}

export function usePredictions() {
  return useQuery({
    queryKey: ["predictions"],
    queryFn: () => api.getPredictions(50),
    refetchInterval: 5000,
  });
}

export function useAttackStages() {
  return useQuery({
    queryKey: ["attack-stage"],
    queryFn: () => api.getAttackStages(),
    refetchInterval: 5000,
  });
}

export function useLatestExplanation() {
  return useQuery({
    queryKey: ["explain", "latest"],
    queryFn: () => api.getLatestExplanation(),
    refetchInterval: 10000,
    retry: 1,
  });
}

export function useNetworkEdges() {
  return useQuery({
    queryKey: ["network", "edges"],
    queryFn: () => api.getNetworkEdges(200),
    refetchInterval: 5000,
  });
}

export function useMetrics() {
  return useQuery({
    queryKey: ["metrics"],
    queryFn: () => api.getMetrics(),
    refetchInterval: 10000,
  });
}

export function useModelInfo() {
  return useQuery({
    queryKey: ["model", "info"],
    queryFn: () => api.getModelInfo(),
    refetchInterval: 15000,
    retry: 1,
  });
}

export function useTrainingRuns() {
  return useQuery({
    queryKey: ["training", "runs"],
    queryFn: () => api.getTrainingRuns(),
    refetchInterval: 3000,
  });
}

export function useRiskScores(entityType?: string) {
  return useQuery({
    queryKey: ["risk", entityType],
    queryFn: () => api.getRiskScores(entityType),
    refetchInterval: 5000,
  });
}

export function usePredict() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (params: { features: Record<string, unknown>; graphSnapshot?: Record<string, unknown> }) =>
      api.predict(params.features, params.graphSnapshot),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["predictions"] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["attack-stage"] });
    },
  });
}

export function usePredictDataset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (params?: { datasetId?: string; windowSeconds?: number; maxRows?: number }) =>
      api.predictDataset(
        params?.datasetId ?? "cicids2017",
        params?.windowSeconds ?? 30,
        params?.maxRows ?? 3000,
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["predictions"] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["attack-stage"] });
      queryClient.invalidateQueries({ queryKey: ["network"] });
      queryClient.invalidateQueries({ queryKey: ["risk"] });
    },
  });
}

export function useReloadModel() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.reloadModel(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["model"] });
      queryClient.invalidateQueries({ queryKey: ["metrics"] });
      queryClient.invalidateQueries({ queryKey: ["health"] });
    },
  });
}

export function useStartTraining() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.startTraining.bind(api),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["training"] });
    },
  });
}

export function useModelRegistry() {
  return useQuery({
    queryKey: ["models", "registry"],
    queryFn: () => api.getModelRegistry(),
    refetchInterval: 20000,
  });
}

export function useActivateModel() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.activateModel(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["models"] });
      queryClient.invalidateQueries({ queryKey: ["model"] });
      queryClient.invalidateQueries({ queryKey: ["metrics"] });
      queryClient.invalidateQueries({ queryKey: ["health"] });
    },
  });
}

export function useDeleteModel() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteModel(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["models"] });
    },
  });
}

export function useGraphStrategies() {
  return useQuery({
    queryKey: ["graph-strategies"],
    queryFn: () => api.getGraphStrategies(),
    staleTime: 5 * 60 * 1000,
  });
}

export function useStudioConfig() {
  return useQuery({
    queryKey: ["studio-config"],
    queryFn: () => api.getStudioConfig(),
    staleTime: 60 * 1000,
  });
}

export function useSaveStudioConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.saveStudioConfig.bind(api),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["studio-config"] });
    },
  });
}

export function useUpdateAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) => api.updateAlert(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export function useDatasets() {
  return useQuery({
    queryKey: ["datasets"],
    queryFn: () => api.getDatasets(),
  });
}

// --- Phase 12: Continual Learning ---

export function useDatasetVersions() {
  return useQuery({
    queryKey: ["cl", "dataset-versions"],
    queryFn: () => api.getDatasetVersions(),
    refetchInterval: 15000,
  });
}

export function useRegisterDataset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.registerDataset.bind(api),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cl"] });
    },
  });
}

export function useDriftReports() {
  return useQuery({
    queryKey: ["cl", "drift"],
    queryFn: () => api.getDrift(),
    refetchInterval: 20000,
  });
}

export function useComputeDrift() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.computeDrift.bind(api),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cl", "drift"] });
    },
  });
}

export function useTrainingHistory(datasetId?: string) {
  return useQuery({
    queryKey: ["cl", "training-history", datasetId],
    queryFn: () => api.getTrainingHistory(datasetId),
    refetchInterval: 10000,
  });
}

export function useApprovalHistory(limit = 100) {
  return useQuery({
    queryKey: ["cl", "approvals", limit],
    queryFn: () => api.getApprovalHistory(limit),
    refetchInterval: 15000,
  });
}

export function useExperiments(datasetId?: string) {
  return useQuery({
    queryKey: ["cl", "experiments", datasetId],
    queryFn: () => api.getExperiments(datasetId),
    refetchInterval: 10000,
  });
}

export function useRetrainCandidate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.retrainCandidate.bind(api),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cl"] });
      queryClient.invalidateQueries({ queryKey: ["models"] });
    },
  });
}

export function useCompareCandidate() {
  return useMutation({
    mutationFn: (candidateId: string) => api.compareCandidate(candidateId),
  });
}

export function useApproveCandidate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (candidateId: string) => api.approveCandidate(candidateId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["models"] });
      queryClient.invalidateQueries({ queryKey: ["model"] });
      queryClient.invalidateQueries({ queryKey: ["cl"] });
      queryClient.invalidateQueries({ queryKey: ["metrics"] });
    },
  });
}

export function useRollbackModel() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.rollbackModel(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["models"] });
      queryClient.invalidateQueries({ queryKey: ["model"] });
      queryClient.invalidateQueries({ queryKey: ["cl"] });
      queryClient.invalidateQueries({ queryKey: ["metrics"] });
    },
  });
}

export function useRollbackInfo() {
  return useQuery({
    queryKey: ["cl", "rollback-info"],
    queryFn: () => api.getRollbackInfo(),
    refetchInterval: 30000,
  });
}

export function useReviewQueue(status?: string) {
  return useQuery({
    queryKey: ["cl", "review", status],
    queryFn: () => api.getReviewQueue(status),
    refetchInterval: 12000,
  });
}

export function useRelabelReview() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, label }: { id: string; label: string }) => api.relabelReview(id, label),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cl", "review"] }),
  });
}

export function useApproveReview() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.approveReview(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cl", "review"] }),
  });
}

export function useKnowledgeBase() {
  return useQuery({
    queryKey: ["cl", "knowledge-base"],
    queryFn: () => api.getKnowledgeBase(),
    refetchInterval: 30000,
  });
}

export function useSocResponse() {
  return useMutation({
    mutationFn: api.getSocResponse.bind(api),
  });
}

export function useSystemHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => api.getHealth(),
    refetchInterval: 15000,
  });
}

export function useAdminHealth() {
  return useQuery({
    queryKey: ["admin", "health"],
    queryFn: () => api.getAdminHealth(),
    refetchInterval: 10000,
  });
}

export function useAdminAuditLogs(limit = 100) {
  return useQuery({
    queryKey: ["admin", "audit-logs", limit],
    queryFn: () => api.getAdminAuditLogs(limit),
    refetchInterval: 30000,
  });
}

export function useAdminApiLogs(limit = 100) {
  return useQuery({
    queryKey: ["admin", "api-logs", limit],
    queryFn: () => api.getAdminApiLogs(limit),
    refetchInterval: 15000,
  });
}

export function useAdminPredictionLogs(limit = 50) {
  return useQuery({
    queryKey: ["admin", "prediction-logs", limit],
    queryFn: () => api.getAdminPredictionLogs(limit),
    refetchInterval: 20000,
  });
}

export function useAdminSystemLogs(limit = 100) {
  return useQuery({
    queryKey: ["admin", "system-logs", limit],
    queryFn: () => api.getAdminSystemLogs(limit),
    refetchInterval: 20000,
  });
}
