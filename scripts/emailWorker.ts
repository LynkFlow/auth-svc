import os from "node:os";
import { randomUUID } from "node:crypto";
import config from "../src/config/env";
import pool from "../src/db/pool";
import { EmailServiceClient } from "../src/services/emailServiceClient";
import { EmailOutboxProcessor } from "../src/services/emailOutboxProcessor";

const workerId = `${os.hostname()}:${process.pid}:${randomUUID()}`;
let stopping = false;
let wakeWorker: (() => void) | undefined;

function wait(milliseconds: number): Promise<void> {
    return new Promise((resolve) => {
        const timer = setTimeout(() => {
            wakeWorker = undefined;
            resolve();
        }, milliseconds);
        wakeWorker = () => {
            clearTimeout(timer);
            wakeWorker = undefined;
            resolve();
        };
    });
}

function requestShutdown(signal: string): void {
    console.log(`${signal} received. Stopping email outbox worker.`);
    stopping = true;
    wakeWorker?.();
}

async function run(): Promise<void> {
    const emailClient = new EmailServiceClient({
        endpointUrl: config.emailServiceUrl,
        timeoutMs: config.emailServiceTimeoutMs,
    });
    const processor = new EmailOutboxProcessor({
        workerId,
        locale: config.emailLocale,
        batchSize: config.emailOutboxBatchSize,
        maxAttempts: config.emailOutboxMaxAttempts,
        lockTimeoutSeconds: config.emailOutboxLockTimeoutSeconds,
        emailClient,
    });

    process.once("SIGINT", () => requestShutdown("SIGINT"));
    process.once("SIGTERM", () => requestShutdown("SIGTERM"));

    console.log("Email outbox worker started.", {
        workerId,
        endpoint: config.emailServiceUrl,
    });

    while (!stopping) {
        try {
            const result = await processor.processBatch();

            if (result.permanentlyFailed > 0) {
                console.error("Email outbox events permanently failed.", result);
            } else if (result.retried > 0) {
                console.warn("Email outbox events scheduled for retry.", result);
            }

            if (result.claimed === config.emailOutboxBatchSize) {
                continue;
            }
        } catch (error) {
            console.error("Email outbox polling failed.", {
                message:
                    error instanceof Error ? error.message : "Unknown error",
            });
        }

        if (!stopping) {
            await wait(config.emailOutboxPollIntervalMs);
        }
    }
}

run()
    .catch((error: unknown) => {
        console.error("Email outbox worker stopped unexpectedly.", {
            message: error instanceof Error ? error.message : "Unknown error",
        });
        process.exitCode = 1;
    })
    .finally(async () => {
        await pool.end();
    });
