import type { AuthenticatedSession } from "../repositories/sessionRepository.js";

declare global {
  namespace Express {
    interface Request {
      validatedBody?: unknown;
      auth?: AuthenticatedSession;
    }
  }
}

export {};
