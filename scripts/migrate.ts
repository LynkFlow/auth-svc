import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import type { QueryResultRow } from "pg";
import pool from "../src/db/pool";

interface AppliedMigrationRow extends QueryResultRow {
    checksum: string;
}

const migrationsDirectory = path.resolve(process.cwd(), "migrations");

function checksum(content: string): string {
    return createHash("sha256").update(content).digest("hex");
}

async function migrate(): Promise<void> {
    const client = await pool.connect();

    try {
        await client.query("SELECT pg_advisory_lock(hashtext('lf_auth_migrations'))");
        await client.query(`
            CREATE TABLE IF NOT EXISTS schema_migrations (
                filename TEXT PRIMARY KEY,
                checksum CHAR(64) NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        const files = fs
            .readdirSync(migrationsDirectory)
            .filter((filename) => /^\d+.*\.sql$/.test(filename))
            .sort();

        for (const filename of files) {
            const migrationPath = path.join(migrationsDirectory, filename);
            const sql = fs.readFileSync(migrationPath, "utf8");
            const migrationChecksum = checksum(sql);
            const { rows } = await client.query<AppliedMigrationRow>(
                "SELECT checksum FROM schema_migrations WHERE filename = $1",
                [filename],
            );

            const appliedMigration = rows[0];
            if (appliedMigration) {
                if (appliedMigration.checksum !== migrationChecksum) {
                    throw new Error(`Applied migration was modified: ${filename}`);
                }

                continue;
            }

            await client.query("BEGIN");
            try {
                await client.query(sql);
                await client.query(
                    "INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)",
                    [filename, migrationChecksum],
                );
                await client.query("COMMIT");
                console.log(`Applied migration: ${filename}`);
            } catch (error) {
                await client.query("ROLLBACK");
                throw error;
            }
        }
    } finally {
        await client
            .query("SELECT pg_advisory_unlock(hashtext('lf_auth_migrations'))")
            .catch(() => undefined);
        client.release();
        await pool.end();
    }
}

migrate().catch((error: unknown) => {
    const databaseError = error as Error & { code?: string };
    console.error("Database migration failed.", {
        code: databaseError.code,
        message: databaseError.message,
    });
    process.exitCode = 1;
});
