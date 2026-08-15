import type { Request, Response } from "express";
import type { HealthService } from "../services/HealthService.js";

export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  // Arrow-function class fields, not prototype methods -- Express calls
  // these as bare references (e.g. `router.get("/live",
  // healthController.liveness)`), which loses `this` unless the method
  // is already bound. See backend-conventions.md.
  liveness = (_req: Request, res: Response): Response => {
    return res.status(200).json({
      success: true,
      data: this.healthService.getLiveness(),
    });
  };

  readiness = async (_req: Request, res: Response): Promise<Response> => {
    return res.status(200).json({
      success: true,
      data: await this.healthService.getReadiness(),
    });
  };
}
