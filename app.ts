import express from "express";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import cors from "cors";
import config from "./src/config/env.js";
import { API_VERSION } from "./src/config/apiVersion.js";
import { requestContext } from "./src/middleware/requestContext.js";
import { createHealthRoutes } from "./src/routes/healthRoutes.js";
import { createAuthRoutes } from "./src/routes/authRoutes.js";
import { buildContainer } from "./src/container.js";
import { errorHandler, notFoundHandler } from "./src/middleware/errorHandler.js";

const app = express();
const container = buildContainer();

if (config.trustProxy !== false) {
  app.set("trust proxy", config.trustProxy);
}

app.disable("x-powered-by");
// Mounted first -- every other middleware/handler (including every
// controller's audit-log calls) relies on req.log/req.requestId already
// existing. See backend-conventions.md's "Logging: pino" section.
app.use(requestContext);
app.use(
  cors({
    origin: config.corsOrigins,
    credentials: true,
  }),
);

app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

app.get("/", (_req, res) => {
  res.status(200).json({
    success: true,
    message: "LF Auth Backend is running",
  });
});

app.use("/health", createHealthRoutes(container.healthController));

app.get("/.well-known/jwks.json", container.authController.jwks);

app.use(
  `/api/${API_VERSION}/auth`,
  createAuthRoutes(container.authController, container.authGuard),
);

app.use(notFoundHandler);
app.use(errorHandler);

export default app;
export { container };
