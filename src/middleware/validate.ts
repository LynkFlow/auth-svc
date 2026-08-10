import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { ZodType } from "zod";
import AppError from "../errors/AppError";

export default function validate(schema: ZodType): RequestHandler {
    return function validationMiddleware(
        req: Request,
        _res: Response,
        next: NextFunction,
    ): void {
        const result = schema.safeParse(req.body);

        if (!result.success) {
            const details = result.error.issues.map((issue) => ({
                field: issue.path.join("."),
                message: issue.message,
            }));

            next(
                new AppError(
                    400,
                    "VALIDATION_ERROR",
                    "The request is invalid.",
                    details,
                ),
            );
            return;
        }

        req.validatedBody = result.data;
        next();
    };
}
