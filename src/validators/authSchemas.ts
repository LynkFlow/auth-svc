import { z } from "zod";

export const loginSchema = z
    .object({
        email: z
            .string({ error: "Email address is required." })
            .trim()
            .min(1, "Email address is required.")
            .max(254, "Email address is too long.")
            .email("Email address must be valid.")
            .transform((value) => value.toLowerCase()),
        password: z
            .string({ error: "Password is required." })
            .min(1, "Password is required.")
            .refine(
                (value) => Buffer.byteLength(value, "utf8") <= 1_024,
                "Password is too long.",
            ),
        rememberMe: z.boolean().optional().default(false),
    })
    .strict();

export type LoginInput = z.infer<typeof loginSchema>;
