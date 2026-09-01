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

export class ApiRequestError extends DataSourceError {
  constructor(message: string, code = "api_request_failed") {
    super(code, message);
    this.name = "ApiRequestError";
  }
}
