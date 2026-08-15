import assert from "node:assert/strict";
import type {
  DeliveryFailure,
  OutboxEvent,
} from "../src/repositories/outboxRepository.js";
import type { EmailSender } from "../src/services/emailServiceClient.js";
import {
  EmailServiceClient,
  EmailServiceResponseError,
  EmailServiceTransportError,
} from "../src/services/emailServiceClient.js";
import { mapOutboxEventToEmail } from "../src/services/emailEventMapper.js";
import {
  EmailOutboxProcessor,
  type OutboxStore,
} from "../src/services/emailOutboxProcessor.js";

function event(overrides: Partial<OutboxEvent> = {}): OutboxEvent {
  return {
    id: "2fcb351c-175c-42fa-a383-a9a6112dbc26",
    eventType: "account.activation.requested",
    aggregateId: "7f86ef14-f9eb-4714-9960-75404d36ca38",
    payload: {
      email: "user@example.com",
      fullName: "Example User",
      organizationName: "Example Company",
      token: "activation-token",
      expiresAt: "2099-08-12T12:00:00.000Z",
    },
    deliveryAttempts: 1,
    idempotencyGeneration: 0,
    ...overrides,
  };
}

class FakeOutboxStore implements OutboxStore {
  readonly events: OutboxEvent[];
  readonly published: string[] = [];
  readonly failures: DeliveryFailure[] = [];

  constructor(events: OutboxEvent[]) {
    this.events = events;
  }

  async claimPendingEvents(): Promise<OutboxEvent[]> {
    return this.events;
  }

  async markPublished(eventId: string): Promise<boolean> {
    this.published.push(eventId);
    return true;
  }

  async markDeliveryFailed(failure: DeliveryFailure): Promise<boolean> {
    this.failures.push(failure);
    return true;
  }
}

function processor(
  outboxStore: OutboxStore,
  emailClient: EmailSender,
  maxAttempts = 10,
): EmailOutboxProcessor {
  return new EmailOutboxProcessor({
    workerId: "test-worker",
    locale: "en",
    batchSize: 10,
    maxAttempts,
    lockTimeoutSeconds: 60,
    emailClient,
    outboxStore,
    random: () => 0.5,
  });
}

describe("email outbox mapping and delivery", () => {
  it("maps every auth email event to the notification-service contract", () => {
    const activation = mapOutboxEventToEmail(event(), "en");
    assert.deepEqual(activation, {
      templateCode: "account.activation.requested",
      locale: "en",
      to: [{ email: "user@example.com", name: "Example User" }],
      variables: {
        fullName: "Example User",
        organizationName: "Example Company",
        token: "activation-token",
        expiresAt: "2099-08-12T12:00:00.000Z",
      },
    });

    const resetRequested = mapOutboxEventToEmail(
      event({
        eventType: "password.reset.requested",
        payload: {
          email: "user@example.com",
          token: "reset-token",
          expiresAt: "2099-08-12T12:00:00.000Z",
        },
      }),
      "en",
    );
    assert.deepEqual(resetRequested.variables, {
      token: "reset-token",
      expiresAt: "2099-08-12T12:00:00.000Z",
    });

    for (const eventType of ["password.reset.completed", "password.changed"]) {
      const notification = mapOutboxEventToEmail(
        event({
          eventType,
          payload: { email: "user@example.com", fullName: null },
        }),
        "en",
      );
      assert.deepEqual(notification.variables, {});
    }
  });

  it("publishes a delivered event using a stable idempotency key", async () => {
    const item = event();
    const store = new FakeOutboxStore([item]);
    const sends: Array<{ key: string; templateCode: string }> = [];
    const emailClient: EmailSender = {
      async send(request, key) {
        sends.push({ key, templateCode: request.templateCode });
      },
    };

    const result = await processor(store, emailClient).processBatch();

    assert.deepEqual(result, {
      claimed: 1,
      published: 1,
      retried: 0,
      permanentlyFailed: 0,
    });
    assert.deepEqual(sends, [
      {
        key: `auth-outbox:${item.id}:0`,
        templateCode: item.eventType,
      },
    ]);
    assert.deepEqual(store.published, [item.id]);
  });

  it("keeps the idempotency key after an ambiguous transport failure", async () => {
    const store = new FakeOutboxStore([event()]);
    const emailClient: EmailSender = {
      async send() {
        throw new EmailServiceTransportError();
      },
    };

    const result = await processor(store, emailClient).processBatch();

    assert.equal(result.retried, 1);
    assert.equal(store.failures[0]?.advanceIdempotencyGeneration, false);
    assert.equal(store.failures[0]?.permanentlyFailed, false);
    assert.equal(store.failures[0]?.error, "EMAIL_SERVICE_TRANSPORT_ERROR");
  });

  it("advances the idempotency generation after a conflict response", async () => {
    const store = new FakeOutboxStore([event({ deliveryAttempts: 2 })]);
    const emailClient: EmailSender = {
      async send() {
        throw new EmailServiceResponseError(409, "EMAIL_SEND_ALREADY_IN_PROGRESS");
      },
    };

    await processor(store, emailClient).processBatch();

    assert.equal(store.failures[0]?.advanceIdempotencyGeneration, true);
    assert.equal(store.failures[0]?.permanentlyFailed, false);
  });

  it("dead-letters malformed events without calling the email service", async () => {
    const store = new FakeOutboxStore([event({ payload: { email: "not-an-email" } })]);
    let sendCalls = 0;
    const emailClient: EmailSender = {
      async send() {
        sendCalls += 1;
      },
    };

    const result = await processor(store, emailClient).processBatch();

    assert.equal(sendCalls, 0);
    assert.equal(result.permanentlyFailed, 1);
    assert.equal(store.failures[0]?.error, "INVALID_EMAIL_EVENT");
    assert.equal(store.failures[0]?.permanentlyFailed, true);
  });

  it("dead-letters expired token emails instead of sending stale links", async () => {
    const store = new FakeOutboxStore([
      event({
        payload: {
          email: "user@example.com",
          fullName: "Example User",
          organizationName: "Example Company",
          token: "expired-token",
          expiresAt: "2020-01-01T00:00:00.000Z",
        },
      }),
    ]);
    let sendCalls = 0;
    const emailClient: EmailSender = {
      async send() {
        sendCalls += 1;
      },
    };

    const result = await processor(store, emailClient).processBatch();

    assert.equal(sendCalls, 0);
    assert.equal(result.permanentlyFailed, 1);
    assert.equal(store.failures[0]?.error, "EMAIL_EVENT_EXPIRED");
  });

  it("email client posts JSON and the outbox idempotency key", async () => {
    let receivedUrl = "";
    let receivedOptions: RequestInit | undefined;
    const client = new EmailServiceClient({
      endpointUrl: "http://localhost:3010/api/v1/emails/send",
      timeoutMs: 1_000,
      fetchImplementation: async (input, options) => {
        // EmailServiceClient always calls fetch with its endpointUrl
        // (a plain string) as `input` -- the parameter's static type is
        // the full fetch() union (string | URL | Request), one member
        // of which (Request) has no meaningful toString(), hence the
        // inline disable rather than a cast (a cast right before
        // String() is flagged as unnecessary since String() itself
        // accepts anything).
        // eslint-disable-next-line @typescript-eslint/no-base-to-string
        receivedUrl = String(input);
        receivedOptions = options;
        return new Response(JSON.stringify({ success: true }), {
          status: 202,
          headers: { "Content-Type": "application/json" },
        });
      },
    });
    const request = mapOutboxEventToEmail(event(), "en");

    await client.send(request, "auth-outbox:test:0");

    assert.equal(receivedUrl, "http://localhost:3010/api/v1/emails/send");
    assert.equal(receivedOptions?.method, "POST");
    assert.equal(
      (receivedOptions?.headers as Record<string, string>)["Idempotency-Key"],
      "auth-outbox:test:0",
    );
    assert.deepEqual(JSON.parse(String(receivedOptions?.body as string)), request);
  });
});
