import express, { type Router } from "express";
import type { HealthController } from "../controllers/HealthController.js";

export function createHealthRoutes(healthController: HealthController): Router {
  const router = express.Router();
  router.get("/live", healthController.liveness);
  router.get("/ready", healthController.readiness);
  return router;
}
