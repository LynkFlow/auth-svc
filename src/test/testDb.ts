import { CamelCasePlugin, Kysely, PostgresDialect } from "kysely";
import type { Database } from "../db/schema.js";

export interface TestDb {
  db: Kysely<Database>;
  query: jest.Mock;
}

/**
 * A real Kysely<Database> wired to a fake pg.Pool whose connect() always
 * returns the same fake client -- lets a repository test assert on the
 * compiled SQL/parameters, or stub a result, with no real Postgres
 * connection. See backend-conventions.md's "SQL query layer: Kysely".
 *
 * The mocked `query` resolves with `command` unset by default -- set it
 * per-test (e.g. `command: "UPDATE"`) whenever the assertion needs
 * numAffectedRows/numUpdatedRows to be populated, matching the real
 * postgres driver's own command-gated behavior (see
 * PostgresDriver#executeQuery).
 */
export function createTestDb(): TestDb {
  const query = jest.fn();
  const client = { query, release: jest.fn() };
  const pool = { connect: jest.fn().mockResolvedValue(client) };

  const db = new Kysely<Database>({
    dialect: new PostgresDialect({ pool: pool as never }),
    plugins: [new CamelCasePlugin()],
  });

  return { db, query };
}
