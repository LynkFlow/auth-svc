import { z } from "zod";
import type { OutboxEvent } from "../repositories/outboxRepository.js";

interface EmailAddress {
  email: string;
  name?: string;
}

export interface SendEmailRequest {
  templateCode: string;
  locale: string;
  to: EmailAddress[];
  variables: Record<string, string | number | boolean>;
}

export class InvalidEmailEventError extends Error {
  constructor(eventType: string) {
    super(`Outbox event '${eventType}' is not a valid email event.`);
    this.name = "InvalidEmailEventError";
  }
}

export class ExpiredEmailEventError extends Error {
  constructor(eventType: string) {
    super(`Outbox event '${eventType}' contains an expired token.`);
    this.name = "ExpiredEmailEventError";
  }
}

const email = z.string().email().max(320);
const nullableName = z.string().trim().min(1).max(200).nullable().optional();
const token = z.string().min(1).max(512);
const expiresAt = z.string().datetime({ offset: true });

const activationRequestedSchema = z.object({
  email,
  fullName: z.string().trim().min(1).max(200),
  organizationName: z.string().trim().min(1).max(200),
  token,
  expiresAt,
});

const accountActivatedSchema = z.object({
  email,
  fullName: nullableName,
});

const passwordResetRequestedSchema = z.object({
  email,
  token,
  expiresAt,
});

const notificationSchema = z.object({
  email,
  fullName: nullableName,
});

function recipient(emailAddress: string, name?: string | null): EmailAddress {
  return name
    ? { email: emailAddress, name: name.slice(0, 128) }
    : { email: emailAddress };
}

function assertTokenNotExpired(eventType: string, expiration: string): void {
  if (new Date(expiration) <= new Date()) {
    throw new ExpiredEmailEventError(eventType);
  }
}

export function mapOutboxEventToEmail(
  event: OutboxEvent,
  locale: string,
): SendEmailRequest {
  switch (event.eventType) {
    case "account.activation.requested": {
      const parsed = activationRequestedSchema.safeParse(event.payload);
      if (!parsed.success) {
        throw new InvalidEmailEventError(event.eventType);
      }
      assertTokenNotExpired(event.eventType, parsed.data.expiresAt);

      return {
        templateCode: event.eventType,
        locale,
        to: [recipient(parsed.data.email, parsed.data.fullName)],
        variables: {
          fullName: parsed.data.fullName,
          organizationName: parsed.data.organizationName,
          token: parsed.data.token,
          expiresAt: parsed.data.expiresAt,
        },
      };
    }
    case "account.activated": {
      const parsed = accountActivatedSchema.safeParse(event.payload);
      if (!parsed.success) {
        throw new InvalidEmailEventError(event.eventType);
      }
      const fullName = parsed.data.fullName ?? "LynkFlow user";
      return {
        templateCode: event.eventType,
        locale,
        to: [recipient(parsed.data.email, parsed.data.fullName)],
        variables: { fullName },
      };
    }
    case "password.reset.requested": {
      const parsed = passwordResetRequestedSchema.safeParse(event.payload);
      if (!parsed.success) {
        throw new InvalidEmailEventError(event.eventType);
      }
      assertTokenNotExpired(event.eventType, parsed.data.expiresAt);

      return {
        templateCode: event.eventType,
        locale,
        to: [recipient(parsed.data.email)],
        variables: {
          token: parsed.data.token,
          expiresAt: parsed.data.expiresAt,
        },
      };
    }
    case "password.reset.completed":
    case "password.changed": {
      const parsed = notificationSchema.safeParse(event.payload);
      if (!parsed.success) {
        throw new InvalidEmailEventError(event.eventType);
      }

      return {
        templateCode: event.eventType,
        locale,
        to: [recipient(parsed.data.email, parsed.data.fullName)],
        variables: {},
      };
    }
    default:
      throw new InvalidEmailEventError(event.eventType);
  }
}
