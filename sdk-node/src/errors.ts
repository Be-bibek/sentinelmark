export class SentinelMarkError extends Error {
  public errorCode: string;
  public requestId: string;

  constructor(message: string, errorCode: string = 'UNKNOWN', requestId: string = '') {
    super(`[${errorCode}] ${message} (Request ID: ${requestId})`);
    this.name = 'SentinelMarkError';
    this.errorCode = errorCode;
    this.requestId = requestId;
  }
}

export class SentinelMarkAuthError extends SentinelMarkError {
  constructor(message: string, errorCode: string, requestId: string) {
    super(message, errorCode, requestId);
    this.name = 'SentinelMarkAuthError';
  }
}

export class SentinelMarkValidationError extends SentinelMarkError {
  constructor(message: string, errorCode: string, requestId: string) {
    super(message, errorCode, requestId);
    this.name = 'SentinelMarkValidationError';
  }
}

export class SentinelMarkRateLimitError extends SentinelMarkError {
  constructor(message: string, errorCode: string, requestId: string) {
    super(message, errorCode, requestId);
    this.name = 'SentinelMarkRateLimitError';
  }
}

export class SentinelMarkApiError extends SentinelMarkError {
  constructor(message: string, errorCode: string, requestId: string) {
    super(message, errorCode, requestId);
    this.name = 'SentinelMarkApiError';
  }
}
