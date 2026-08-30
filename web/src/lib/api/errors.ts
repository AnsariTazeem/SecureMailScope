export class DataSourceError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "DataSourceError";
    this.code = code;
  }
}

export class CaptureValidationError extends DataSourceError {
  constructor(message: string) {
    super("capture_validation", message);
    this.name = "CaptureValidationError";
  }
}

export class AnalysisNotFoundError extends DataSourceError {
  constructor(analysisId: string) {
    super(
      "analysis_not_found",
      `No analysis is available for ${analysisId}.`,
    );
    this.name = "AnalysisNotFoundError";
  }
}

export class ApiUnavailableError extends DataSourceError {
  constructor() {
    super(
      "api_unavailable",
      "The production HTTP API is not available. This frontend does not invent API results. Use NEXT_PUBLIC_DATA_MODE=mock for the Prototype Analysis Dataset.",
    );
    this.name = "ApiUnavailableError";
  }
}

export class ApiRequestError extends DataSourceError {
  constructor(message: string) {
    super("api_request_failed", message);
    this.name = "ApiRequestError";
  }
}
