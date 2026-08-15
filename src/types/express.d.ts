import type { Logger } from "pino";
import type { AuthenticatedSession } from "../repositories/SessionRepository.js";

declare global {
  namespace Express {
    interface Request {
      validatedBody?: unknown;
      auth?: AuthenticatedSession;
      /** Set by requestContext -- a pino child logger scoped to this request's ID. */
      log: Logger;
      /** Set by requestContext -- same ID as req.log's bound requestId, as a plain string. */
      requestId: string;
    }
  }
}

export {};
