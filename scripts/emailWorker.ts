import os from "node:os";
import { randomUUID } from "node:crypto";
import { CamelCasePlugin, Kysely, PostgresDialect } from "kysely";
import config from "../src/config/env.js";
import pool from "../src/db/pool.js";
import type { Database } from "../src/db/schema.js";
import logger from "../src/logging/logger.js";
import { OutboxRepository } from "../src/repositories/OutboxRepository.js";
import { EmailServiceClient } from "../src/services/EmailServiceClient.js";
import { EmailOutboxProcessor } from "../src/services/EmailOutboxProcessor.js";

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
  logger.info({ signal }, "stopping email outbox worker");
  stopping = true;
  wakeWorker?.();
}

async function run(): Promise<void> {
  const emailClient = new EmailServiceClient({
    endpointUrl: config.emailServiceUrl,
    timeoutMs: config.emailServiceTimeoutMs,
  });
  // This script is its own small composition root for the background
  // worker process -- there's no HTTP container.ts to reuse here, so it
  // builds its own Kysely<Database> from the same pool and constructs the
  // one repository/processor pair it needs directly, matching the "one
  // place wires everything with new" principle at process-entry-point
  // scope (backend-conventions.md).
  const db = new Kysely<Database>({
    dialect: new PostgresDialect({ pool }),
    plugins: [new CamelCasePlugin()],
  });
  const outboxRepository = new OutboxRepository(db);
  const processor = new EmailOutboxProcessor({
    workerId,
    locale: config.emailLocale,
    batchSize: config.emailOutboxBatchSize,
    maxAttempts: config.emailOutboxMaxAttempts,
    lockTimeoutSeconds: config.emailOutboxLockTimeoutSeconds,
    emailClient,
    outboxStore: outboxRepository,
  });

  process.once("SIGINT", () => requestShutdown("SIGINT"));
  process.once("SIGTERM", () => requestShutdown("SIGTERM"));

  logger.info(
    { workerId, endpoint: config.emailServiceUrl },
    "email outbox worker started",
  );

  while (!stopping) {
    try {
      const result = await processor.processBatch();

      if (result.permanentlyFailed > 0) {
        logger.error(result, "email outbox events permanently failed");
      } else if (result.retried > 0) {
        logger.warn(result, "email outbox events scheduled for retry");
      }

      if (result.claimed === config.emailOutboxBatchSize) {
        continue;
      }
    } catch (error) {
      logger.error({ err: error }, "email outbox polling failed");
    }

    if (!stopping) {
      await wait(config.emailOutboxPollIntervalMs);
    }
  }
}

void run()
  .catch((error: unknown) => {
    logger.error({ err: error }, "email outbox worker stopped unexpectedly");
    process.exitCode = 1;
  })
  .finally(async () => {
    await pool.end();
  });
