import { sql, type Kysely } from "kysely";
import type { Database } from "../db/schema.js";

export class HealthRepository {
  constructor(private readonly db: Kysely<Database>) {}

  async databaseIsReachable(): Promise<boolean> {
    const result = await sql<{ reachable: number }>`SELECT 1 AS reachable`.execute(
      this.db,
    );
    return result.rows[0]?.reachable === 1;
  }
}
