import app from "./app";
import config from "./src/config/env";
import pool from "./src/db/pool";
import { initializeTokenService } from "./src/services/tokenService";

async function start(): Promise<void> {
    await initializeTokenService();

    const server = app.listen(config.port, () => {
        console.log(`Server running on port ${config.port}`);
    });

    function shutdown(signal: string): void {
        console.log(`${signal} received. Shutting down gracefully.`);

        server.close(async (error?: Error) => {
            await pool.end();

            if (error) {
                console.error("HTTP server shutdown failed.", error);
                process.exit(1);
            }

            process.exit(0);
        });
    }

    process.once("SIGINT", () => shutdown("SIGINT"));
    process.once("SIGTERM", () => shutdown("SIGTERM"));
}

start().catch(async (error: unknown) => {
    console.error("Application startup failed.", {
        message: error instanceof Error ? error.message : "Unknown error",
    });
    await pool.end();
    process.exitCode = 1;
});
