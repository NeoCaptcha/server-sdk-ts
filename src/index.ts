const VERIFY_URL = 'https://neocaptcha.com/api/v1/verify';
const DEFAULT_TIMEOUT_MS = 10_000;

export type VerificationErrorCode =
  | 'invalid_solution'
  | 'expired_solution'
  | 'solution_already_used'
  | 'site_key_mismatch'
  | 'hostname_mismatch';

export type NeoCaptchaErrorCode =
  | 'invalid_options'
  | 'invalid_request'
  | 'invalid_credentials'
  | 'site_disabled'
  | 'rate_limited'
  | 'internal_error'
  | 'service_unavailable'
  | 'network_error'
  | 'request_timeout'
  | 'request_aborted'
  | 'invalid_response';

export interface VerifyTokenOptions {
  solution: string;
  siteKey: string;
  siteSecret: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export type VerifyTokenResult =
  | {
      success: true;
      requestId?: string;
    }
  | {
      success: false;
      error: {
        code: VerificationErrorCode;
        message: string;
      };
      requestId?: string;
    };

interface ApiErrorBody {
  error?: {
    code?: NeoCaptchaErrorCode;
    message?: string;
    retryable?: boolean;
  };
  requestId?: string;
}

export class NeoCaptchaError extends Error {
  readonly code: NeoCaptchaErrorCode;
  readonly status?: number;
  readonly requestId?: string;
  readonly retryable: boolean;
  readonly cause?: unknown;

  constructor(
    message: string,
    options: {
      code: NeoCaptchaErrorCode;
      status?: number;
      requestId?: string;
      retryable?: boolean;
      cause?: unknown;
    },
  ) {
    super(message);

    this.name = 'NeoCaptchaError';
    this.code = options.code;
    this.status = options.status;
    this.requestId = options.requestId;
    this.retryable = options.retryable ?? false;
    this.cause = options.cause;

    Object.setPrototypeOf(this, NeoCaptchaError.prototype);
  }
}

export async function verifyToken(
  options: VerifyTokenOptions,
): Promise<VerifyTokenResult> {
  validateOptions(options);

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  let timedOut = false;

  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const abort = () => controller.abort();

  if (options.signal?.aborted) {
    controller.abort();
  } else {
    options.signal?.addEventListener('abort', abort, { once: true });
  }

  try {
    const response = await fetch(VERIFY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        solution: options.solution,
        siteKey: options.siteKey,
        secret: options.siteSecret,
      }),
      signal: controller.signal,
    });

    const requestId = response.headers.get('x-request-id') ?? undefined;

    const body = await readJson(response, requestId);

    if (!response.ok) {
      const apiError = body as ApiErrorBody;

      throw new NeoCaptchaError(
        apiError.error?.message ??
          `NeoCaptcha returned HTTP ${response.status}.`,
        {
          code: apiError.error?.code ?? getHttpErrorCode(response.status),
          status: response.status,
          requestId: apiError.requestId ?? requestId,
          retryable:
            (apiError.error?.retryable ?? response.status === 429) ||
            response.status >= 500,
        },
      );
    }

    if (!isVerifyTokenResult(body)) {
      throw new NeoCaptchaError('NeoCaptcha returned an unexpected response.', {
        code: 'invalid_response',
        status: response.status,
        requestId,
      });
    }

    return {
      ...body,
      requestId: body.requestId ?? requestId,
    };
  } catch (error) {
    if (error instanceof NeoCaptchaError) {
      throw error;
    }

    if (controller.signal.aborted) {
      throw new NeoCaptchaError(
        timedOut
          ? `NeoCaptcha verification timed out after ${timeoutMs}ms.`
          : 'NeoCaptcha verification was aborted.',
        {
          code: timedOut ? 'request_timeout' : 'request_aborted',
          retryable: timedOut,
          cause: error,
        },
      );
    }

    throw new NeoCaptchaError('Unable to connect to NeoCaptcha.', {
      code: 'network_error',
      retryable: true,
      cause: error,
    });
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener('abort', abort);
  }
}

function validateOptions(options: VerifyTokenOptions): void {
  const requiredFields = [
    ['solution', options?.solution],
    ['siteKey', options?.siteKey],
    ['siteSecret', options?.siteSecret],
  ] as const;

  for (const [name, value] of requiredFields) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw new NeoCaptchaError(`${name} must be a non-empty string.`, {
        code: 'invalid_options',
      });
    }
  }

  if (
    options.timeoutMs !== undefined &&
    (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0)
  ) {
    throw new NeoCaptchaError('timeoutMs must be a positive number.', {
      code: 'invalid_options',
    });
  }
}

async function readJson(
  response: Response,
  requestId?: string,
): Promise<unknown> {
  try {
    return await response.json();
  } catch (cause) {
    throw new NeoCaptchaError('NeoCaptcha returned an invalid JSON response.', {
      code: 'invalid_response',
      status: response.status,
      requestId,
      retryable: response.status >= 500,
      cause,
    });
  }
}

function isVerifyTokenResult(value: unknown): value is VerifyTokenResult {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const result = value as Record<string, unknown>;

  if (result.success === true) {
    return true;
  }

  if (
    result.success !== false ||
    !result.error ||
    typeof result.error !== 'object'
  ) {
    return false;
  }

  const error = result.error as Record<string, unknown>;

  return typeof error.code === 'string' && typeof error.message === 'string';
}

function getHttpErrorCode(status: number): NeoCaptchaErrorCode {
  switch (status) {
    case 400:
      return 'invalid_request';
    case 401:
      return 'invalid_credentials';
    case 403:
      return 'site_disabled';
    case 429:
      return 'rate_limited';
    case 503:
      return 'service_unavailable';
    default:
      return 'internal_error';
  }
}
