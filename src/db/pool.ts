import { Pool } from "pg";
import config from "../config/env.js";

const pool = new Pool({
  connectionString: config.databaseUrl,
  max: 10,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 30_000,
  allowExitOnIdle: config.nodeEnv === "test",
});

pool.on("error", (error: Error & { code?: string }) => {
  console.error("Unexpected PostgreSQL pool error.", {
    code: error.code,
    message: error.message,
  });
});

export default pool;
