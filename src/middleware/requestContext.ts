import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import logger from "../logging/logger.js";

/**
 * Mounted first, before every other middleware -- everything downstream
 * (including errorHandler and every controller's audit-log calls) relies
 * on req.log/req.requestId already existing. Doubles as the access log via
 * the res "finish" listener.
 */
export function requestContext(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const requestId = req.get("x-request-id") ?? randomUUID();
  req.log = logger.child({ requestId });
  // A plain string mirror of req.log's bound requestId -- so a controller
  // building an AuditLogEntry doesn't need to reach into pino's internal
  // bindings() API just to get the correlation ID back out.
  req.requestId = requestId;
  res.set("x-request-id", requestId);

  const startedAt = Date.now();
  res.on("finish", () => {
    req.log.info(
      {
        method: req.method,
        path: req.originalUrl,
        statusCode: res.statusCode,
        durationMs: Date.now() - startedAt,
      },
      "request completed",
    );
  });

  next();
}
