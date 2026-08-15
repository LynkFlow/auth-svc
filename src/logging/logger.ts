import pino, { type Logger } from "pino";
import config from "../config/env.js";

// One process-wide logger. Classes that need to log take this as a
// constructor argument (like any other dependency) rather than importing
// it ad hoc -- see backend-conventions.md's "Logging: pino" section.
const logger: Logger = pino({
  level: config.nodeEnv === "production" ? "info" : "debug",
  // Pretty-printing only in local dev -- it spawns a worker thread via
  // pino's transport, which is unnecessary overhead in production (plain
  // JSON is what a log aggregator wants anyway) and can leave a dangling
  // worker thread that keeps Jest's process from exiting cleanly in test.
  ...(config.nodeEnv === "development"
    ? { transport: { target: "pino-pretty" } }
    : {}),
});

export default logger;
