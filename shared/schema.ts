import { relations, sql } from "drizzle-orm";
import {
  boolean,
  doublePrecision,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { z } from "zod";

export const roleEnum = pgEnum("role", ["admin", "analyst", "viewer", "operator"]);
export const alertSeverityEnum = pgEnum("alert_severity", ["critical", "high", "medium", "low", "info"]);
export const alertStatusEnum = pgEnum("alert_status", ["open", "investigating", "resolved", "false_positive"]);
export const nodeTypeEnum = pgEnum("node_type", [
  "ip_address", "host", "server", "router", "switch", "iot_device", "user",
]);
export const nodeStatusEnum = pgEnum("node_status", ["online", "offline", "suspicious", "compromised"]);
export const edgeProtocolEnum = pgEnum("edge_protocol", [
  "tcp", "udp", "http", "https", "ssh", "dns", "ftp", "smtp", "mqtt", "other",
]);
export const attackStageEnum = pgEnum("attack_stage", [
  "reconnaissance", "scanning", "credential_attack", "privilege_escalation",
  "lateral_movement", "persistence", "data_exfiltration", "impact", "normal",
]);
export const datasetStatusEnum = pgEnum("dataset_status", ["pending", "processing", "ready", "failed"]);
export const trainingStatusEnum = pgEnum("training_status", [
  "queued", "running", "completed", "failed", "cancelled",
]);
export const modelArchitectureEnum = pgEnum("model_architecture", [
  "gat", "tgn", "graphsage", "gcn", "tgat", "dysat",
]);
export const reportFormatEnum = pgEnum("report_format", ["pdf", "csv", "json"]);

export const roles = pgTable("roles", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: roleEnum("name").notNull().unique(),
  description: text("description").notNull(),
  permissions: jsonb("permissions").$type<string[]>().notNull().default([]),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  roleId: uuid("role_id").notNull().references(() => roles.id),
  emailVerified: boolean("email_verified").notNull().default(false),
  emailVerifyToken: varchar("email_verify_token", { length: 255 }),
  totpSecret: text("totp_secret"),
  totpEnabled: boolean("totp_enabled").notNull().default(false),
  resetPasswordToken: varchar("reset_password_token", { length: 255 }),
  resetPasswordExpires: timestamp("reset_password_expires", { withTimezone: true }),
  lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("users_email_idx").on(table.email),
  index("users_role_idx").on(table.roleId),
]);

export const sessions = pgTable("sessions", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  refreshTokenHash: text("refresh_token_hash").notNull(),
  userAgent: text("user_agent"),
  ipAddress: varchar("ip_address", { length: 45 }),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("sessions_user_idx").on(table.userId),
  index("sessions_expires_idx").on(table.expiresAt),
]);

export const datasets = pgTable("datasets", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: varchar("name", { length: 255 }).notNull(),
  source: varchar("source", { length: 100 }).notNull(),
  filePath: text("file_path"),
  fileType: varchar("file_type", { length: 20 }).notNull(),
  recordCount: integer("record_count").default(0),
  featureCount: integer("feature_count").default(0),
  status: datasetStatusEnum("status").notNull().default("pending"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
  uploadedBy: uuid("uploaded_by").references(() => users.id),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  processedAt: timestamp("processed_at", { withTimezone: true }),
}, (table) => [
  index("datasets_source_idx").on(table.source),
  index("datasets_status_idx").on(table.status),
  index("datasets_created_idx").on(table.createdAt),
]);

export const mlModels = pgTable("ml_models", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: varchar("name", { length: 255 }).notNull(),
  version: varchar("version", { length: 50 }).notNull(),
  architecture: modelArchitectureEnum("architecture").notNull(),
  datasetId: uuid("dataset_id").references(() => datasets.id),
  filePath: text("file_path").notNull(),
  hyperparameters: jsonb("hyperparameters").$type<Record<string, unknown>>().default({}),
  metrics: jsonb("metrics").$type<Record<string, number>>().default({}),
  isActive: boolean("is_active").notNull().default(false),
  createdBy: uuid("created_by").references(() => users.id),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("ml_models_active_idx").on(table.isActive),
  index("ml_models_created_idx").on(table.createdAt),
]);

export const trainingRuns = pgTable("training_runs", {
  id: uuid("id").primaryKey().defaultRandom(),
  modelId: uuid("model_id").references(() => mlModels.id),
  datasetId: uuid("dataset_id").notNull().references(() => datasets.id),
  architecture: modelArchitectureEnum("architecture").notNull(),
  status: trainingStatusEnum("status").notNull().default("queued"),
  hyperparameters: jsonb("hyperparameters").$type<Record<string, unknown>>().notNull(),
  epochs: integer("epochs").notNull().default(50),
  currentEpoch: integer("current_epoch").notNull().default(0),
  trainLoss: doublePrecision("train_loss"),
  valLoss: doublePrecision("val_loss"),
  trainAccuracy: doublePrecision("train_accuracy"),
  valAccuracy: doublePrecision("val_accuracy"),
  metrics: jsonb("metrics").$type<Record<string, unknown>>().default({}),
  gpuUtilization: doublePrecision("gpu_utilization"),
  startedBy: uuid("started_by").references(() => users.id),
  startedAt: timestamp("started_at", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  errorMessage: text("error_message"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("training_runs_status_idx").on(table.status),
  index("training_runs_created_idx").on(table.createdAt),
]);

export const networkNodes = pgTable("network_nodes", {
  id: uuid("id").primaryKey().defaultRandom(),
  externalId: varchar("external_id", { length: 255 }).notNull().unique(),
  ipAddress: varchar("ip_address", { length: 45 }).notNull(),
  macAddress: varchar("mac_address", { length: 17 }),
  hostname: varchar("hostname", { length: 255 }),
  nodeType: nodeTypeEnum("node_type").notNull().default("host"),
  status: nodeStatusEnum("status").notNull().default("online"),
  os: varchar("os", { length: 255 }),
  vendor: varchar("vendor", { length: 255 }),
  openPorts: jsonb("open_ports").$type<number[]>().default([]),
  subnet: varchar("subnet", { length: 50 }),
  department: varchar("department", { length: 100 }),
  riskScore: doublePrecision("risk_score").notNull().default(0),
  packets: integer("packets").default(0),
  bytes: integer("bytes").default(0),
  failedLogins: integer("failed_logins").default(0),
  connectionCount: integer("connection_count").default(0),
  features: jsonb("features").$type<Record<string, number>>().default({}),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("network_nodes_ip_idx").on(table.ipAddress),
  index("network_nodes_status_idx").on(table.status),
  index("network_nodes_risk_idx").on(table.riskScore),
]);

export const networkEdges = pgTable("network_edges", {
  id: uuid("id").primaryKey().defaultRandom(),
  sourceNodeId: uuid("source_node_id").notNull().references(() => networkNodes.id, { onDelete: "cascade" }),
  targetNodeId: uuid("target_node_id").notNull().references(() => networkNodes.id, { onDelete: "cascade" }),
  protocol: edgeProtocolEnum("protocol").notNull().default("tcp"),
  latencyMs: doublePrecision("latency_ms"),
  bandwidthMbps: doublePrecision("bandwidth_mbps"),
  packetCount: integer("packet_count").default(0),
  direction: varchar("direction", { length: 20 }).default("bidirectional"),
  weight: doublePrecision("weight").notNull().default(1),
  features: jsonb("features").$type<Record<string, number>>().default({}),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull().defaultNow(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("network_edges_source_idx").on(table.sourceNodeId),
  index("network_edges_target_idx").on(table.targetNodeId),
  index("network_edges_timestamp_idx").on(table.timestamp),
]);

export const attackGraphs = pgTable("attack_graphs", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: varchar("name", { length: 255 }).notNull(),
  windowSeconds: integer("window_seconds").notNull().default(30),
  nodeCount: integer("node_count").notNull().default(0),
  edgeCount: integer("edge_count").notNull().default(0),
  snapshotData: jsonb("snapshot_data").$type<Record<string, unknown>>().notNull(),
  datasetId: uuid("dataset_id").references(() => datasets.id),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("attack_graphs_dataset_idx").on(table.datasetId),
  index("attack_graphs_created_idx").on(table.createdAt),
]);

export const predictions = pgTable("predictions", {
  id: uuid("id").primaryKey().defaultRandom(),
  modelId: uuid("model_id").references(() => mlModels.id),
  sourceNodeId: uuid("source_node_id").references(() => networkNodes.id),
  targetNodeId: uuid("target_node_id").references(() => networkNodes.id),
  attackType: varchar("attack_type", { length: 100 }).notNull(),
  attackStage: attackStageEnum("attack_stage").notNull(),
  predictedNextStage: attackStageEnum("predicted_next_stage"),
  threatLevel: alertSeverityEnum("threat_level").notNull(),
  probability: doublePrecision("probability").notNull(),
  confidence: doublePrecision("confidence").notNull(),
  riskScore: doublePrecision("risk_score").notNull(),
  isCompromised: boolean("is_compromised").notNull().default(false),
  explanation: jsonb("explanation").$type<Record<string, unknown>>(),
  rawFeatures: jsonb("raw_features").$type<Record<string, unknown>>(),
  graphSnapshotId: uuid("graph_snapshot_id").references(() => attackGraphs.id),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("predictions_attack_type_idx").on(table.attackType),
  index("predictions_stage_idx").on(table.attackStage),
  index("predictions_created_idx").on(table.createdAt),
  index("predictions_model_idx").on(table.modelId),
]);

export const riskScores = pgTable("risk_scores", {
  id: uuid("id").primaryKey().defaultRandom(),
  entityType: varchar("entity_type", { length: 50 }).notNull(),
  entityId: varchar("entity_id", { length: 255 }).notNull(),
  entityName: varchar("entity_name", { length: 255 }).notNull(),
  nodeRisk: doublePrecision("node_risk").default(0),
  subnetRisk: doublePrecision("subnet_risk").default(0),
  departmentRisk: doublePrecision("department_risk").default(0),
  organizationRisk: doublePrecision("organization_risk").default(0),
  propagationRisk: doublePrecision("propagation_risk").default(0),
  businessImpact: doublePrecision("business_impact").default(0),
  factors: jsonb("factors").$type<Record<string, number>>().default({}),
  computedAt: timestamp("computed_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("risk_scores_entity_idx").on(table.entityType, table.entityId),
  index("risk_scores_computed_idx").on(table.computedAt),
]);

export const alerts = pgTable("alerts", {
  id: uuid("id").primaryKey().defaultRandom(),
  title: varchar("title", { length: 500 }).notNull(),
  description: text("description"),
  severity: alertSeverityEnum("severity").notNull(),
  status: alertStatusEnum("status").notNull().default("open"),
  attackType: varchar("attack_type", { length: 100 }),
  attackStage: attackStageEnum("attack_stage"),
  mitreTactic: varchar("mitre_tactic", { length: 100 }),
  mitreTechnique: varchar("mitre_technique", { length: 100 }),
  sourceIp: varchar("source_ip", { length: 45 }),
  targetIp: varchar("target_ip", { length: 45 }),
  protocol: varchar("protocol", { length: 20 }),
  predictionId: uuid("prediction_id").references(() => predictions.id),
  assignedTo: uuid("assigned_to").references(() => users.id),
  acknowledgedAt: timestamp("acknowledged_at", { withTimezone: true }),
  resolvedAt: timestamp("resolved_at", { withTimezone: true }),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("alerts_severity_idx").on(table.severity),
  index("alerts_status_idx").on(table.status),
  index("alerts_created_idx").on(table.createdAt),
]);

export const reports = pgTable("reports", {
  id: uuid("id").primaryKey().defaultRandom(),
  title: varchar("title", { length: 500 }).notNull(),
  format: reportFormatEnum("format").notNull(),
  filePath: text("file_path"),
  content: jsonb("content").$type<Record<string, unknown>>(),
  generatedBy: uuid("generated_by").references(() => users.id),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const notifications = pgTable("notifications", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  title: varchar("title", { length: 500 }).notNull(),
  message: text("message").notNull(),
  type: varchar("type", { length: 50 }).notNull(),
  isRead: boolean("is_read").notNull().default(false),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("notifications_user_idx").on(table.userId),
  index("notifications_read_idx").on(table.isRead),
]);

export const auditLogs = pgTable("audit_logs", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").references(() => users.id),
  action: varchar("action", { length: 100 }).notNull(),
  resource: varchar("resource", { length: 100 }).notNull(),
  resourceId: varchar("resource_id", { length: 255 }),
  details: jsonb("details").$type<Record<string, unknown>>().default({}),
  ipAddress: varchar("ip_address", { length: 45 }),
  userAgent: text("user_agent"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("audit_logs_user_idx").on(table.userId),
  index("audit_logs_action_idx").on(table.action),
  index("audit_logs_created_idx").on(table.createdAt),
]);

export const systemLogs = pgTable("system_logs", {
  id: uuid("id").primaryKey().defaultRandom(),
  level: varchar("level", { length: 20 }).notNull(),
  service: varchar("service", { length: 50 }).notNull(),
  message: text("message").notNull(),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("system_logs_level_idx").on(table.level),
  index("system_logs_service_idx").on(table.service),
  index("system_logs_created_idx").on(table.createdAt),
]);

export const usersRelations = relations(users, ({ one, many }) => ({
  role: one(roles, { fields: [users.roleId], references: [roles.id] }),
  sessions: many(sessions),
  alerts: many(alerts),
}));

export const networkNodesRelations = relations(networkNodes, ({ many }) => ({
  outgoingEdges: many(networkEdges, { relationName: "sourceEdges" }),
  incomingEdges: many(networkEdges, { relationName: "targetEdges" }),
}));

export const networkEdgesRelations = relations(networkEdges, ({ one }) => ({
  sourceNode: one(networkNodes, {
    fields: [networkEdges.sourceNodeId],
    references: [networkNodes.id],
    relationName: "sourceEdges",
  }),
  targetNode: one(networkNodes, {
    fields: [networkEdges.targetNodeId],
    references: [networkNodes.id],
    relationName: "targetEdges",
  }),
}));

export const insertUserSchema = createInsertSchema(users, {
  email: z.string().email(),
  name: z.string().min(2).max(255),
}).omit({ id: true, createdAt: true, updatedAt: true, passwordHash: true });

export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(128),
  name: z.string().min(2).max(255),
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  totpCode: z.string().length(6).optional(),
});

export type Role = typeof roles.$inferSelect;
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Session = typeof sessions.$inferSelect;
export type Dataset = typeof datasets.$inferSelect;
export type MlModel = typeof mlModels.$inferSelect;
export type TrainingRun = typeof trainingRuns.$inferSelect;
export type NetworkNode = typeof networkNodes.$inferSelect;
export type NetworkEdge = typeof networkEdges.$inferSelect;
export type AttackGraph = typeof attackGraphs.$inferSelect;
export type Prediction = typeof predictions.$inferSelect;
export type RiskScore = typeof riskScores.$inferSelect;
export type Alert = typeof alerts.$inferSelect;
export type Report = typeof reports.$inferSelect;
export type Notification = typeof notifications.$inferSelect;
export type AuditLog = typeof auditLogs.$inferSelect;
