import { z } from "zod";

export const chainObservabilitySchema = z.enum([
  "observed",
  "derived",
  "policy_inferred",
  "not_observable",
  "incomplete_capture",
  "session_secrets_required",
  "not_applicable",
]);

export const confidenceLevelSchema = z.enum([
  "high",
  "medium",
  "low",
  "not_scored",
]);

export const analysisStatusSchema = z.enum(["complete", "partial", "failed"]);

export const stageStatusSchema = z.enum([
  "complete",
  "partial",
  "failed",
  "not_run",
  "skipped",
]);

export const stageIdSchema = z.enum([
  "intake",
  "capture_provenance",
  "stream_reconstruction",
  "event_reconstruction",
  "tls_extraction",
  "fact_derivation",
  "policy_evaluation",
  "anomaly_scoring",
  "report_generation",
  "artifact_manifest",
]);

export const engineStatusSchema = z.enum([
  "not_run",
  "complete",
  "partial",
  "failed",
  "unavailable",
]);

export const tls13SecretsStatusSchema = z.enum([
  "not_supplied",
  "authorized_supplied",
]);

export const evidenceSourceKindSchema = z.enum([
  "capinfos",
  "tshark_field",
  "tshark_follow_stream",
  "tshark_expert",
  "cryptography_library",
  "derived_state_machine",
]);

export const evidenceRedactionSchema = z.enum([
  "none",
  "redacted_local_part",
  "redacted_credential",
  "hashed",
  "excerpt_only",
]);

export const protocolEventTypeSchema = z.enum([
  "tcp_connected",
  "server_greeting",
  "capability_request",
  "capability_advertised",
  "tls_upgrade_requested",
  "tls_upgrade_accepted",
  "tls_upgrade_rejected",
  "client_hello",
  "server_hello",
  "certificate_message",
  "key_exchange_observed",
  "handshake_finished",
  "encrypted_application_data",
  "plaintext_command_after_tls_offer",
  "session_closed",
  "capture_boundary_reached",
]);

export const protocolStateSchema = z.enum([
  "connection_open",
  "greeting",
  "ready",
  "tls_offered",
  "tls_requested",
  "tls_negotiating",
  "tls_active",
  "tls_failed",
  "closed",
  "unknown",
]);

export const eventStatusSchema = z.enum([
  "observed",
  "inferred",
  "incomplete_capture",
  "not_observable",
]);

export const observationKindSchema = z.enum([
  "tls_negotiated_version",
  "selected_cipher_suite",
  "record_layer_legacy_version",
  "supported_versions",
  "key_share_group",
  "psk_key_exchange_mode",
  "signature_algorithm",
  "public_key_algorithm",
  "public_key_length",
  "certificate_subject",
  "certificate_issuer",
  "certificate_san",
  "certificate_validity_window",
  "certificate_fingerprint",
  "certificate_chain_structure",
  "certificate_serial_number",
  "certificate_basic_constraints",
  "certificate_key_usage",
  "certificate_structure_parsed",
  "certificate_signature_chain_checked",
  "certificate_trusted_path_validated",
  "certificate_service_identity_validated",
  "certificate_revocation_checked",
  "session_resumption_indicator",
  "tls13_certificate_unavailable",
]);

export const ruleOutcomeSchema = z.enum([
  "matched",
  "not_matched",
  "not_applicable",
  "insufficient_evidence",
  "suppressed_by_profile",
]);

export const ruleReasonCodeSchema = z.enum([
  "rule_matched",
  "rule_not_matched",
  "not_applicable_protocol",
  "facts_missing",
  "evidence_incomplete",
  "profile_suppressed",
]);

export const severityLevelSchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);

export const findingCategorySchema = z.enum([
  "encryption_transition",
  "tls_version",
  "key_exchange",
  "certificate_validity",
  "certificate_identity",
  "authentication",
  "sensitive_data",
  "configuration",
  "not_classified",
]);

export const anomalyBandSchema = z.enum([
  "normal",
  "attention",
  "elevated",
  "anomalous",
]);

export const recommendationPrioritySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);

export const recommendationScopeSchema = z.enum([
  "session",
  "capture",
  "service",
  "deployment",
]);

export const automationStatusSchema = z.enum(["advisory_only"]);

export const limitationCodeSchema = z.enum([
  "derived_from_observed",
  "not_observable_encrypted_tls13",
  "not_present",
  "capture_incomplete",
  "unknown_insufficient_evidence",
  "session_secrets_required",
  "field_unavailable",
  "not_assessed",
  "not_applicable",
]);

export const protocolSchema = z.enum(["smtp", "imap", "pop3", "unknown"]);

export const directionSchema = z.enum([
  "client_to_server",
  "server_to_client",
  "unknown",
]);

export const completeStatusSchema = z.enum([
  "complete",
  "capture_incomplete",
  "insufficient",
]);

export const captureFormatSchema = z.enum(["pcap", "pcapng", "unknown"]);

export type ChainObservability = z.infer<typeof chainObservabilitySchema>;
export type ConfidenceLevel = z.infer<typeof confidenceLevelSchema>;
export type Protocol = z.infer<typeof protocolSchema>;
export type SeverityLevel = z.infer<typeof severityLevelSchema>;
