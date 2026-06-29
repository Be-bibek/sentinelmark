import {
  SentinelMarkAuthError,
  SentinelMarkValidationError,
  SentinelMarkRateLimitError,
  SentinelMarkApiError,
  SentinelMarkError,
} from './errors';

export interface SentinelMarkOptions {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
  maxRetries?: number;
  debug?: boolean;
}

export interface EvaluateOptions {
  productSlug: string;
  eventType: string;
  payload: Record<string, any>;
  metadata?: Record<string, any>;
  idempotencyKey?: string;
}

export class EventsResource {
  constructor(private client: SentinelMark) {}

  async evaluate(options: EvaluateOptions): Promise<any> {
    const headers: Record<string, string> = {};
    if (options.idempotencyKey) {
      headers['Idempotency-Key'] = options.idempotencyKey;
    }

    const body = {
      product_slug: options.productSlug,
      api_version: 'v1',
      protocol_version: '1.0',
      sdk_version: this.client.sdkVersion,
      event_type: options.eventType,
      timestamp: new Date().toISOString(),
      payload: options.payload,
      metadata: options.metadata || {},
    };

    return this.client._request('POST', '/api/v1/events', body, headers);
  }
}

export class SentinelMark {
  private apiKey: string;
  private baseUrl: string;
  private timeout: number;
  private maxRetries: number;
  private debug: boolean;
  public readonly sdkVersion = '1.0.0';

  public events: EventsResource;

  constructor(options: SentinelMarkOptions) {
    if (!options.apiKey) {
      throw new Error('apiKey is required');
    }
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl || 'https://api.sentinelmark.ai').replace(/\/$/, '');
    this.timeout = options.timeout || 30000;
    this.maxRetries = options.maxRetries ?? 3;
    this.debug = options.debug || false;

    this.events = new EventsResource(this);
  }

  private logDebug(message: string, ...args: any[]) {
    if (this.debug) {
      console.debug(`[SentinelMark] ${message}`, ...args);
    }
  }

  private logWarn(message: string, ...args: any[]) {
    console.warn(`[SentinelMark] ${message}`, ...args);
  }

  async _request(method: string, path: string, body?: any, customHeaders?: Record<string, string>): Promise<any> {
    const url = `${this.baseUrl}${path}`;
    
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
      'X-SentinelMark-SDK': 'node',
      'X-SentinelMark-Version': this.sdkVersion,
      'User-Agent': `sentinelmark-node/${this.sdkVersion}`,
      'X-Request-Id': crypto.randomUUID(),
      ...customHeaders,
    };

    let retries = 0;
    while (true) {
      try {
        this.logDebug(`Request: ${method} ${url}`, { headers });
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        const response = await fetch(url, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });
        
        clearTimeout(timeoutId);

        if (response.ok) {
          return await response.json();
        }

        if ([429, 500, 502, 503, 504].includes(response.status) && retries < this.maxRetries) {
          retries++;
          const sleepTime = Math.pow(2, retries) * 250;
          this.logWarn(`Request failed with ${response.status}. Retrying in ${sleepTime}ms...`);
          await new Promise(resolve => setTimeout(resolve, sleepTime));
          continue;
        }

        await this._handleError(response);

      } catch (error: any) {
        if (retries < this.maxRetries) {
          retries++;
          const sleepTime = Math.pow(2, retries) * 250;
          this.logWarn(`Network error: ${error.message}. Retrying in ${sleepTime}ms...`);
          await new Promise(resolve => setTimeout(resolve, sleepTime));
          continue;
        }
        throw new SentinelMarkError(`Network error: ${error.message}`);
      }
    }
  }

  private async _handleError(response: Response): Promise<never> {
    let errorCode = 'UNKNOWN';
    let message = 'Unknown error';
    let requestId = '';

    try {
      const data = await response.json();
      errorCode = data.error_code || errorCode;
      message = data.message || message;
      requestId = data.request_id || requestId;
    } catch {
      message = await response.text();
    }

    if (response.status === 401 || response.status === 403) {
      throw new SentinelMarkAuthError(message, errorCode, requestId);
    } else if (response.status === 400) {
      throw new SentinelMarkValidationError(message, errorCode, requestId);
    } else if (response.status === 429) {
      throw new SentinelMarkRateLimitError(message, errorCode, requestId);
    } else if (response.status >= 500) {
      throw new SentinelMarkApiError(message, errorCode, requestId);
    } else {
      throw new SentinelMarkError(message, errorCode, requestId);
    }
  }
}
