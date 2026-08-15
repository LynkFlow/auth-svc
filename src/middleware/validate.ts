import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { ZodType } from "zod";
import { ValidationError } from "../errors/ValidationErrors.js";

export default function validate(schema: ZodType): RequestHandler {
  return function validationMiddleware(
    req: Request,
    _res: Response,
    next: NextFunction,
  ): void {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      // Field-keyed, not an array of {field, message} objects --
      // matches @lynkflow/types' ApiError.fieldErrors shape
      // (business-domain.md: validation messages must identify the
      // offending field). First issue per field wins.
      const fieldErrors: Record<string, string> = {};
      for (const issue of result.error.issues) {
        const field = issue.path.join(".") || "_root";
        fieldErrors[field] ??= issue.message;
      }

      next(new ValidationError(fieldErrors));
      return;
    }

    req.validatedBody = result.data;
    next();
  };
}
