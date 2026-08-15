import type { SendEmailRequest } from "./emailEventMapper.js";

export class EmailServiceResponseError extends Error {
  readonly status: number;
  readonly errorCode: string | null;

  constructor(status: number, errorCode: string | null) {
    super(`Email service returned HTTP ${status}.`);
    this.name = "EmailServiceResponseError";
    this.status = status;
    this.errorCode = errorCode;
  }
}

export class EmailServiceTransportError extends Error {
  constructor() {
    super("Email service request failed before a response was received.");
    this.name = "EmailServiceTransportError";
  }
}

export interface EmailServiceClientOptions {
  endpointUrl: string;
  timeoutMs: number;
  fetchImplementation?: typeof fetch;
}

export interface EmailSender {
  send(request: SendEmailRequest, idempotencyKey: string): Promise<void>;
}

export class EmailServiceClient implements EmailSender {
  private readonly endpointUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImplementation: typeof fetch;

  constructor({
    endpointUrl,
    timeoutMs,
    fetchImplementation = fetch,
  }: EmailServiceClientOptions) {
    this.endpointUrl = endpointUrl;
    this.timeoutMs = timeoutMs;
    this.fetchImplementation = fetchImplementation;
  }

  async send(request: SendEmailRequest, idempotencyKey: string): Promise<void> {
    let response: Response;

    try {
      response = await this.fetchImplementation(this.endpointUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify(request),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch {
      throw new EmailServiceTransportError();
    }

    if (response.ok) {
      return;
    }

    let errorCode: string | null = null;
    try {
      const body = (await response.json()) as {
        error?: { code?: unknown };
      };
      if (typeof body.error?.code === "string") {
        errorCode = body.error.code.slice(0, 128);
      }
    } catch {
      // The status code is sufficient when the response is not JSON.
    }

    throw new EmailServiceResponseError(response.status, errorCode);
  }
}
