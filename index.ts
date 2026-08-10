import app from "./app";
import config from "./src/config/env";
import pool from "./src/db/pool";

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
