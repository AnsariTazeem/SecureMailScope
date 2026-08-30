import { z } from "zod";

import {
  analysisStatusSchema,
  anomalyBandSchema,
  automationStatusSchema,
  captureFormatSchema,
  chainObservabilitySchema,
  completeStatusSchema,
  confidenceLevelSchema,
  directionSchema,
  engineStatusSchema,
  eventStatusSchema,
  evidenceRedactionSchema,
  evidenceSourceKindSchema,
  findingCategorySchema,
  limitationCodeSchema,
  observationKindSchema,
  protocolEventTypeSchema,
  protocolSchema,
  protocolStateSchema,
  recommendationPrioritySchema,
  recommendationScopeSchema,
  ruleOutcomeSchema,
  ruleReasonCodeSchema,
  severityLevelSchema,
  stageIdSchema,
  stageStatusSchema,
  tls13SecretsStatusSchema,
} from "./enums";
import {
  ANALYSIS_ID,
  ANOMALY_ID,
  ARTIFACT_ID,
  CAPTURE_ID,
  EVALUATION_ID,
  EVENT_ID,
  EVIDENCE_ID,
  FACT_ID,
  FINDING_ID,
  OBSERVATION_ID,
  POLICY_CONTRIBUTION_ID,
  POLICY_RISK_ID,
  RECOMMENDATION_ID,
  SEMVER,
  SESSION_ID,
  SHA256_DIGEST,
  SHA256_KEY,
} from "./ids";

export const SCHEMA_ID = "urn:securemailscope:schema:chain-of-proof:1.0.0";
export const CHAIN_SCHEMA_VERSION = "1.0.0";
export const ANOMALY_INTERPRETATION_NOTE =
  "Anomalous behavior is not proof of malicious activity.";

const isoDatetime = z
  .string()
  .regex(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/,
    "Expected UTC ISO-8601 datetime",
  );

const jsonValue: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(jsonValue),
    z.record(z.string(), jsonValue),
  ]),
);

export const analysisLimitationSchema = z.object({
  code: limitationCodeSchema,
  summary: z.string(),
  detail: z.string().default(""),
});

export const standardsReferenceSchema = z.object({
  id: z.string(),
  section: z.string().nullable().optional(),
});

export const endpointSchema = z.object({
  ip: z.string(),
  port: z.number().int().min(0).max(65535),
});

export const analysisManifestSchema = z.object({
  analysis_id: z.string().regex(ANALYSIS_ID),
  chain_schema_version: z.string().regex(SEMVER),
  analysis_status: analysisStatusSchema,
  created_at: isoDatetime,
  started_at: isoDatetime,
  completed_at: isoDatetime.nullable(),
  analyzer_version: z.string(),
  tshark_version: z.string().nullable(),
  rule_engine_status: engineStatusSchema,
  rule_pack_id: z.string().nullable(),
  rule_pack_version: z.string().nullable(),
  ml_engine_status: engineStatusSchema,
  model_id: z.string().nullable(),
  model_version: z.string().nullable(),
  configuration_digest: z.string().regex(SHA256_DIGEST),
  tls13_authorized_secrets: tls13SecretsStatusSchema,
  limitations: z.array(analysisLimitationSchema),
});

export const captureProvenanceSchema = z.object({
  capture_id: z.string().regex(CAPTURE_ID),
  original_filename_sanitized: z.string(),
  format: captureFormatSchema,
  size_bytes: z.number().int().min(0),
  sha256: z.string().regex(SHA256_DIGEST),
  packet_count: z.number().int().min(0),
  captured_at_start: isoDatetime.nullable(),
  captured_at_end: isoDatetime.nullable(),
  link_layer_types: z.array(z.string()),
  snaplen: z.number().int().nullable(),
  truncated_packet_count: z.number().int().min(0),
  capture_warnings: z.array(z.string()),
  ingestion_tool_versions: z.record(z.string(), z.string()),
});

export const sessionSchema = z.object({
  session_id: z.string().regex(SESSION_ID),
  stable_session_key: z.string().regex(SHA256_KEY),
  capture_id: z.string().regex(CAPTURE_ID),
  tcp_stream_id: z.number().int().min(0),
  source_endpoint: endpointSchema,
  destination_endpoint: endpointSchema,
  first_frame: z.number().int().min(1),
  last_frame: z.number().int().min(1),
  started_at: isoDatetime,
  ended_at: isoDatetime,
  packet_count: z.number().int().min(0),
  byte_count: z.number().int().min(0),
  protocol: protocolSchema,
  protocol_confidence: confidenceLevelSchema,
  classification_evidence_ids: z.array(z.string()),
  capture_completeness: completeStatusSchema,
  limitations: z.array(analysisLimitationSchema),
});

export const evidenceReferenceSchema = z.object({
  evidence_id: z.string().regex(EVIDENCE_ID),
  capture_id: z.string().regex(CAPTURE_ID),
  capture_sha256: z.string().regex(SHA256_DIGEST),
  session_id: z.string().regex(SESSION_ID),
  frame_numbers: z.array(z.number().int().min(1)).min(1),
  occurrence_index: z.number().int().min(0),
  timestamp_start: isoDatetime,
  timestamp_end: isoDatetime,
  direction: directionSchema,
  source_kind: evidenceSourceKindSchema,
  source_field: z.string(),
  normalized_value: z.string(),
  safe_excerpt: z.string(),
  display_filter: z.string(),
  observability: z.literal("observed"),
  redaction: evidenceRedactionSchema,
  extractor_version: z.string(),
});

export const protocolEventSchema = z.object({
  event_id: z.string().regex(EVENT_ID),
  session_id: z.string().regex(SESSION_ID),
  sequence_index: z.number().int().min(0),
  event_type: protocolEventTypeSchema,
  protocol: protocolSchema,
  state_before: protocolStateSchema,
  state_after: protocolStateSchema,
  timestamp: isoDatetime,
  direction: directionSchema,
  evidence_ids: z.array(z.string()),
  event_status: eventStatusSchema,
  observability: chainObservabilitySchema,
  limitations: z.array(analysisLimitationSchema),
});

export const cryptoObservationSchema = z.object({
  observation_id: z.string().regex(OBSERVATION_ID),
  session_id: z.string().regex(SESSION_ID),
  kind: observationKindSchema,
  value: jsonValue,
  normalized_value: z.string(),
  observability: chainObservabilitySchema,
  evidence_ids: z.array(z.string()),
  limitations: z.array(analysisLimitationSchema),
});

export const derivedFactSchema = z.object({
  fact_id: z.string().regex(FACT_ID),
  session_id: z.string().regex(SESSION_ID),
  fact_type: z.string(),
  value: jsonValue,
  derivation_id: z.string(),
  derivation_version: z.string().regex(SEMVER),
  source_event_ids: z.array(z.string()),
  source_observation_ids: z.array(z.string()),
  source_fact_ids: z.array(z.string()),
  observability: chainObservabilitySchema,
  confidence_level: confidenceLevelSchema,
  confidence_basis: z.array(z.string()).min(1),
  limitations: z.array(analysisLimitationSchema),
});

export const ruleEvaluationSchema = z.object({
  evaluation_id: z.string().regex(EVALUATION_ID),
  session_id: z.string().regex(SESSION_ID),
  rule_id: z.string(),
  rule_version: z.string().regex(SEMVER),
  profile_id: z.string(),
  evaluated_at: isoDatetime,
  input_fact_ids: z.array(z.string()),
  input_snapshot: z.record(z.string(), jsonValue),
  outcome: ruleOutcomeSchema,
  reason_code: ruleReasonCodeSchema,
  generated_finding_id: z.string().regex(FINDING_ID).nullable(),
});

export const findingSchema = z.object({
  finding_id: z.string().regex(FINDING_ID),
  stable_finding_key: z.string().regex(SHA256_KEY),
  analysis_id: z.string().regex(ANALYSIS_ID),
  session_id: z.string().regex(SESSION_ID),
  rule_evaluation_id: z.string().regex(EVALUATION_ID),
  rule_id: z.string(),
  rule_version: z.string().regex(SEMVER),
  title: z.string(),
  category: findingCategorySchema,
  severity: severityLevelSchema,
  policy_risk_contribution: z.number().int().min(0),
  evidence_confidence: confidenceLevelSchema,
  observability: chainObservabilitySchema,
  fact_ids: z.array(z.string()).min(1),
  evidence_ids: z.array(z.string()).min(1),
  rationale: z.string(),
  impact: z.string(),
  recommendation_id: z.string().regex(RECOMMENDATION_ID),
  standards_references: z.array(standardsReferenceSchema),
  limitations: z.array(analysisLimitationSchema),
  created_at: isoDatetime,
});

export const anomalyResultSchema = z.object({
  anomaly_result_id: z.string().regex(ANOMALY_ID),
  session_id: z.string().regex(SESSION_ID),
  model_id: z.string(),
  model_version: z.string().regex(SEMVER),
  feature_schema_version: z.string().regex(SEMVER),
  feature_snapshot: z.record(z.string(), jsonValue),
  raw_score: z.number().finite(),
  normalized_score: z.number().min(0).max(1).finite(),
  threshold: z.number().finite(),
  band: anomalyBandSchema,
  unusual_feature_indicators: z.array(z.string()),
  linked_fact_ids: z.array(z.string()).optional(),
  linked_observation_ids: z.array(z.string()).optional(),
  evidence_ids: z.array(z.string()).optional(),
  interpretation_note: z.literal(ANOMALY_INTERPRETATION_NOTE),
  limitations: z.array(analysisLimitationSchema),
});

export const recommendationSchema = z.object({
  recommendation_id: z.string().regex(RECOMMENDATION_ID),
  title: z.string(),
  summary: z.string(),
  priority: recommendationPrioritySchema,
  affected_finding_ids: z.array(z.string()),
  action_steps: z.array(z.string()),
  verification_steps: z.array(z.string()),
  standards_references: z.array(standardsReferenceSchema),
  scope: recommendationScopeSchema,
  automation_status: automationStatusSchema,
});

export const policyRiskContributionSchema = z.object({
  contribution_id: z.string().regex(POLICY_CONTRIBUTION_ID),
  rule_id: z.string(),
  rule_version: z.string().regex(SEMVER),
  finding_id: z.string().regex(FINDING_ID),
  severity: severityLevelSchema,
  policy_risk_contribution: z.number().int().min(0),
  evidence_confidence: confidenceLevelSchema,
  confidence_factor: z.number().gt(0),
  confidence_adjusted_points: z.number().int().min(0),
});

export const policyRiskSummarySchema = z.object({
  policy_risk_id: z.string().regex(POLICY_RISK_ID),
  analysis_id: z.string().regex(ANALYSIS_ID),
  profile_id: z.string(),
  uncapped_score: z.number().int().min(0),
  capped_score: z.number().int().min(0).max(100),
  contributions: z.array(policyRiskContributionSchema),
  limitations: z.array(analysisLimitationSchema),
});

export const stageDiagnosticSchema = z.object({
  stage: stageIdSchema,
  status: stageStatusSchema,
  limitation: analysisLimitationSchema.nullable().optional(),
  runtime_seconds: z.number().min(0).finite().default(0),
});

export const analysisExecutionSchema = z.object({
  tool_versions: z.record(z.string(), z.string()).default({}),
  stage_diagnostics: z.array(stageDiagnosticSchema).default([]),
  note: z
    .string()
    .default("Execution envelope; not part of reproducible chain content."),
});

export const artifactManifestSchema = z.object({
  artifact_manifest_id: z.string().regex(ARTIFACT_ID),
  analysis_id: z.string().regex(ANALYSIS_ID),
  capture_sha256: z.string().regex(SHA256_DIGEST),
  canonical_json_sha256: z.string().regex(SHA256_DIGEST),
  html_report_sha256: z.string().regex(SHA256_DIGEST).nullable(),
  pdf_report_sha256: z.string().regex(SHA256_DIGEST).nullable(),
  rule_pack_sha256: z.string().regex(SHA256_DIGEST).nullable(),
  model_artifact_sha256: z.string().regex(SHA256_DIGEST).nullable(),
  generated_at: isoDatetime,
  signature_algorithm: z.string().nullable(),
  signature: z.string().nullable(),
});

export const chainOfProofSchema = z.object({
  schema_id: z.literal(SCHEMA_ID),
  chain_schema_version: z.literal(CHAIN_SCHEMA_VERSION),
  analysis: analysisManifestSchema,
  execution: analysisExecutionSchema,
  captures: z.array(captureProvenanceSchema).min(1),
  sessions: z.array(sessionSchema),
  evidence: z.array(evidenceReferenceSchema),
  protocol_events: z.array(protocolEventSchema),
  crypto_observations: z.array(cryptoObservationSchema),
  derived_facts: z.array(derivedFactSchema),
  rule_evaluations: z.array(ruleEvaluationSchema),
  findings: z.array(findingSchema),
  policy_risk: policyRiskSummarySchema.nullable(),
  anomaly_results: z.array(anomalyResultSchema),
  recommendations: z.array(recommendationSchema),
  artifacts: z.array(artifactManifestSchema),
});

export type ChainOfProof = z.infer<typeof chainOfProofSchema>;
export type AnalysisManifest = z.infer<typeof analysisManifestSchema>;
export type CaptureProvenance = z.infer<typeof captureProvenanceSchema>;
export type Session = z.infer<typeof sessionSchema>;
export type Finding = z.infer<typeof findingSchema>;
export type PolicyRiskSummary = z.infer<typeof policyRiskSummarySchema>;
export type AnomalyResult = z.infer<typeof anomalyResultSchema>;
export type AnalysisLimitation = z.infer<typeof analysisLimitationSchema>;
export type StageDiagnostic = z.infer<typeof stageDiagnosticSchema>;
