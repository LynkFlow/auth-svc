import type { AuthenticatedSession } from "../repositories/sessionRepository";

declare global {
    namespace Express {
        interface Request {
            validatedBody?: unknown;
            auth?: AuthenticatedSession;
        }
    }
}

export {};
