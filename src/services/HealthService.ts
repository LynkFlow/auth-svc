import { ServiceNotReadyError } from "../errors/ServiceErrors.js";
import type { HealthRepository } from "../repositories/HealthRepository.js";

export interface HealthStatus {
  status: "ok";
  timestamp: string;
}

export class HealthService {
  constructor(private readonly healthRepository: HealthRepository) {}

  getLiveness(): HealthStatus {
    return this.healthy();
  }

  async getReadiness(): Promise<HealthStatus> {
    try {
      if (await this.healthRepository.databaseIsReachable()) {
        return this.healthy();
      }
    } catch {
      // The public response intentionally omits infrastructure details.
    }

    throw new ServiceNotReadyError();
  }

  private healthy(): HealthStatus {
    return {
      status: "ok",
      timestamp: new Date().toISOString(),
    };
  }
}
