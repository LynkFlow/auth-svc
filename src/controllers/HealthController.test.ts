import type { Request, Response } from "express";
import { HealthController } from "./HealthController.js";
import AppError from "../errors/AppError.js";
import { ServiceNotReadyError } from "../errors/ServiceErrors.js";
import type { HealthService, HealthStatus } from "../services/HealthService.js";

function mockHealthService(overrides: {
  getLiveness?: jest.Mock;
  getReadiness?: jest.Mock;
}): HealthService {
  return {
    getLiveness: overrides.getLiveness ?? jest.fn(),
    getReadiness: overrides.getReadiness ?? jest.fn(),
  } as unknown as HealthService;
}

function mockResponse(): { status: jest.Mock; json: jest.Mock } {
  const res: { status: jest.Mock; json: jest.Mock } = {
    status: jest.fn(),
    json: jest.fn(),
  };
  res.status.mockReturnValue(res);
  return res;
}

describe("HealthController", () => {
  it("liveness responds 200 with the service's status, bound correctly", () => {
    const status: HealthStatus = { status: "ok", timestamp: "2026-08-16T00:00:00.000Z" };
    const controller = new HealthController(
      mockHealthService({ getLiveness: jest.fn().mockReturnValue(status) }),
    );
    const res = mockResponse();

    // Called as a bare reference, the way Express actually calls it
    // (router.get("/live", controller.liveness)) -- this is exactly the
    // case an unbound prototype method would break.
    const { liveness } = controller;
    liveness({} as Request, res as unknown as Response);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ success: true, data: status });
  });

  it("readiness responds 200 with the service's status when ready", async () => {
    const status: HealthStatus = { status: "ok", timestamp: "2026-08-16T00:00:00.000Z" };
    const controller = new HealthController(
      mockHealthService({ getReadiness: jest.fn().mockResolvedValue(status) }),
    );
    const res = mockResponse();

    const { readiness } = controller;
    await readiness({} as Request, res as unknown as Response);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ success: true, data: status });
  });

  it("readiness propagates the service's AppError instead of swallowing it", async () => {
    const controller = new HealthController(
      mockHealthService({
        getReadiness: jest.fn().mockRejectedValue(new ServiceNotReadyError()),
      }),
    );
    const res = mockResponse();

    await expect(
      controller.readiness({} as Request, res as unknown as Response),
    ).rejects.toBeInstanceOf(AppError);
  });
});
