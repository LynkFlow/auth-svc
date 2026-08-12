import * as outboxRepository from "../repositories/outboxRepository";
import type { OutboxEvent } from "../repositories/outboxRepository";
import type { DeliveryFailure } from "../repositories/outboxRepository";
import {
    EmailServiceResponseError,
    EmailServiceTransportError,
} from "./emailServiceClient";
import type { EmailSender } from "./emailServiceClient";
import {
    ExpiredEmailEventError,
    InvalidEmailEventError,
    mapOutboxEventToEmail,
} from "./emailEventMapper";

interface EmailOutboxProcessorOptions {
    workerId: string;
    locale: string;
    batchSize: number;
    maxAttempts: number;
    lockTimeoutSeconds: number;
    emailClient: EmailSender;
    outboxStore?: OutboxStore;
    random?: () => number;
}

export interface OutboxStore {
    claimPendingEvents(
        workerId: string,
        batchSize: number,
        lockTimeoutSeconds: number,
    ): Promise<OutboxEvent[]>;
    markPublished(eventId: string, workerId: string): Promise<boolean>;
    markDeliveryFailed(failure: DeliveryFailure): Promise<boolean>;
}

export interface ProcessBatchResult {
    claimed: number;
    published: number;
    retried: number;
    permanentlyFailed: number;
}

interface FailureDecision {
    permanentlyFailed: boolean;
    advanceIdempotencyGeneration: boolean;
    error: string;
}

function idempotencyKey(event: OutboxEvent): string {
    return `auth-outbox:${event.id}:${event.idempotencyGeneration}`;
}

function classifyFailure(
    error: unknown,
    reachedMaximumAttempts: boolean,
): FailureDecision {
    if (error instanceof InvalidEmailEventError) {
        return {
            permanentlyFailed: true,
            advanceIdempotencyGeneration: false,
            error: "INVALID_EMAIL_EVENT",
        };
    }

    if (error instanceof ExpiredEmailEventError) {
        return {
            permanentlyFailed: true,
            advanceIdempotencyGeneration: false,
            error: "EMAIL_EVENT_EXPIRED",
        };
    }

    if (error instanceof EmailServiceResponseError) {
        const retryableStatus =
            error.status === 408 ||
            error.status === 409 ||
            error.status === 425 ||
            error.status === 429 ||
            error.status >= 500;
        return {
            permanentlyFailed: reachedMaximumAttempts || !retryableStatus,
            advanceIdempotencyGeneration: error.status === 409,
            error: error.errorCode
                ? `EMAIL_SERVICE_${error.status}_${error.errorCode}`
                : `EMAIL_SERVICE_HTTP_${error.status}`,
        };
    }

    if (error instanceof EmailServiceTransportError) {
        return {
            permanentlyFailed: reachedMaximumAttempts,
            advanceIdempotencyGeneration: false,
            error: "EMAIL_SERVICE_TRANSPORT_ERROR",
        };
    }

    return {
        permanentlyFailed: reachedMaximumAttempts,
        advanceIdempotencyGeneration: false,
        error: "EMAIL_DELIVERY_UNEXPECTED_ERROR",
    };
}

export class EmailOutboxProcessor {
    private readonly workerId: string;
    private readonly locale: string;
    private readonly batchSize: number;
    private readonly maxAttempts: number;
    private readonly lockTimeoutSeconds: number;
    private readonly emailClient: EmailSender;
    private readonly outboxStore: OutboxStore;
    private readonly random: () => number;

    constructor({
        workerId,
        locale,
        batchSize,
        maxAttempts,
        lockTimeoutSeconds,
        emailClient,
        outboxStore = outboxRepository,
        random = Math.random,
    }: EmailOutboxProcessorOptions) {
        this.workerId = workerId;
        this.locale = locale;
        this.batchSize = batchSize;
        this.maxAttempts = maxAttempts;
        this.lockTimeoutSeconds = lockTimeoutSeconds;
        this.emailClient = emailClient;
        this.outboxStore = outboxStore;
        this.random = random;
    }

    private nextAttemptAt(deliveryAttempts: number): Date {
        const exponentialSeconds = Math.min(
            15 * 60,
            5 * 2 ** Math.min(deliveryAttempts - 1, 8),
        );
        const jitter = 0.75 + this.random() * 0.5;
        return new Date(Date.now() + exponentialSeconds * jitter * 1_000);
    }

    private async processEvent(
        event: OutboxEvent,
    ): Promise<"published" | "retried" | "permanentlyFailed"> {
        try {
            const request = mapOutboxEventToEmail(event, this.locale);
            await this.emailClient.send(request, idempotencyKey(event));
            const updated = await this.outboxStore.markPublished(
                event.id,
                this.workerId,
            );

            if (!updated) {
                throw new Error("The outbox event claim was lost.");
            }

            return "published";
        } catch (error) {
            const decision = classifyFailure(
                error,
                event.deliveryAttempts >= this.maxAttempts,
            );
            await this.outboxStore.markDeliveryFailed({
                eventId: event.id,
                workerId: this.workerId,
                error: decision.error,
                nextAttemptAt: this.nextAttemptAt(event.deliveryAttempts),
                permanentlyFailed: decision.permanentlyFailed,
                advanceIdempotencyGeneration:
                    decision.advanceIdempotencyGeneration,
            });

            return decision.permanentlyFailed
                ? "permanentlyFailed"
                : "retried";
        }
    }

    async processBatch(): Promise<ProcessBatchResult> {
        const events = await this.outboxStore.claimPendingEvents(
            this.workerId,
            this.batchSize,
            this.lockTimeoutSeconds,
        );
        const outcomes = await Promise.all(
            events.map((event) => this.processEvent(event)),
        );

        return {
            claimed: events.length,
            published: outcomes.filter((outcome) => outcome === "published")
                .length,
            retried: outcomes.filter((outcome) => outcome === "retried").length,
            permanentlyFailed: outcomes.filter(
                (outcome) => outcome === "permanentlyFailed",
            ).length,
        };
    }
}
