import { HealthService } from "./HealthService.js";
import AppError from "../errors/AppError.js";
import type { HealthRepository } from "../repositories/HealthRepository.js";

function mockRepository(databaseIsReachable: jest.Mock): HealthRepository {
  return { databaseIsReachable } as unknown as HealthRepository;
}

describe("HealthService", () => {
  it("getLiveness returns ok status without touching the repository", () => {
    const databaseIsReachable = jest.fn();
    const service = new HealthService(mockRepository(databaseIsReachable));

    const status = service.getLiveness();

    expect(status.status).toBe("ok");
    expect(typeof status.timestamp).toBe("string");
    expect(databaseIsReachable).not.toHaveBeenCalled();
  });

  it("getReadiness returns ok status when the repository reports reachable", async () => {
    const databaseIsReachable = jest.fn().mockResolvedValue(true);
    const service = new HealthService(mockRepository(databaseIsReachable));

    const status = await service.getReadiness();

    expect(status.status).toBe("ok");
  });

  it("getReadiness throws a 503 AppError when the repository reports unreachable", async () => {
    const databaseIsReachable = jest.fn().mockResolvedValue(false);
    const service = new HealthService(mockRepository(databaseIsReachable));

    await expect(service.getReadiness()).rejects.toMatchObject({
      statusCode: 503,
      code: "SERVICE_NOT_READY",
    });
  });

  it("getReadiness throws the same 503 AppError when the repository itself throws", async () => {
    const databaseIsReachable = jest.fn().mockRejectedValue(new Error("connection refused"));
    const service = new HealthService(mockRepository(databaseIsReachable));

    await expect(service.getReadiness()).rejects.toBeInstanceOf(AppError);
  });
});
