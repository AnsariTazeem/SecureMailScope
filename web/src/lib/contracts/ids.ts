export const SHA256_DIGEST = /^[0-9a-f]{64}$/;
export const SHA256_KEY = /^sha256:[0-9a-f]{64}$/;
export const SEMVER = /^\d+\.\d+\.\d+$/;
export const RECOMMENDATION_ID = /^REC-[A-Z0-9]+(-[A-Z0-9]+)*$/;

export const compactId = (prefix: string) =>
  new RegExp(`^${prefix}_[0-9a-f]{16}$`);

export const ANALYSIS_ID = compactId("ana");
export const CAPTURE_ID = compactId("cap");
export const SESSION_ID = compactId("ses");
export const EVIDENCE_ID = compactId("ev");
export const EVENT_ID = compactId("eve");
export const OBSERVATION_ID = compactId("obs");
export const FACT_ID = compactId("fact");
export const EVALUATION_ID = compactId("eval");
export const FINDING_ID = compactId("fnd");
export const ANOMALY_ID = compactId("anm");
export const ARTIFACT_ID = compactId("art");
export const POLICY_RISK_ID = compactId("polr");
export const POLICY_CONTRIBUTION_ID = compactId("plc");
