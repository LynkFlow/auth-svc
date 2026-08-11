import { z } from "zod";

const activationToken = z
    .string({ error: "Activation token is required." })
    .min(1, "Activation token is required.")
    .max(512, "Activation token is too long.");

const activationPassword = z
    .string({ error: "Password is required." })
    .min(1, "Password is required.")
    .refine(
        (value) => Buffer.byteLength(value, "utf8") <= 1_024,
        "Password is too long.",
    );

const passwordResetToken = z
    .string({ error: "Password reset token is required." })
    .min(1, "Password reset token is required.")
    .max(512, "Password reset token is too long.");

const emailAddress = z
    .string({ error: "Email address is required." })
    .trim()
    .min(1, "Email address is required.")
    .max(254, "Email address is too long.")
    .email("Invalid email format.")
    .transform((value) => value.toLowerCase());

const passwordConfirmation = z
    .string({ error: "Password confirmation is required." })
    .min(1, "Password confirmation is required.")
    .refine(
        (value) => Buffer.byteLength(value, "utf8") <= 1_024,
        "Password confirmation is too long.",
    );

export const loginSchema = z
    .object({
        email: emailAddress,
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

export const validateActivationSchema = z
    .object({
        token: activationToken,
    })
    .strict();

export const completeActivationSchema = z
    .object({
        token: activationToken,
        password: activationPassword.optional(),
        confirmPassword: z
            .string()
            .min(1, "Password confirmation is required.")
            .refine(
                (value) => Buffer.byteLength(value, "utf8") <= 1_024,
                "Password confirmation is too long.",
            )
            .optional(),
        termsAccepted: z.boolean({
            error: "Terms & Conditions acceptance is required.",
        }),
        privacyPolicyAccepted: z.boolean({
            error: "Privacy Policy acceptance is required.",
        }),
    })
    .strict()
    .superRefine((value, context) => {
        if (
            value.password === undefined &&
            value.confirmPassword !== undefined
        ) {
            context.addIssue({
                code: "custom",
                path: ["password"],
                message: "Password is required.",
            });
        }

        if (
            value.password !== undefined &&
            value.confirmPassword === undefined
        ) {
            context.addIssue({
                code: "custom",
                path: ["confirmPassword"],
                message: "Password confirmation is required.",
            });
        }

        if (
            value.password !== undefined &&
            value.confirmPassword !== undefined &&
            value.password !== value.confirmPassword
        ) {
            context.addIssue({
                code: "custom",
                path: ["confirmPassword"],
                message: "Password confirmation does not match.",
            });
        }

        if (!value.termsAccepted) {
            context.addIssue({
                code: "custom",
                path: ["termsAccepted"],
                message: "Terms & Conditions acceptance is required.",
            });
        }

        if (!value.privacyPolicyAccepted) {
            context.addIssue({
                code: "custom",
                path: ["privacyPolicyAccepted"],
                message: "Privacy Policy acceptance is required.",
            });
        }
    });

export type ValidateActivationInput = z.infer<
    typeof validateActivationSchema
>;
export type CompleteActivationInput = z.infer<
    typeof completeActivationSchema
>;

export const signupSchema = z
    .object({
        accountType: z.enum([
            "real_estate_developer",
            "brokerage_company",
            "sales_agent",
        ]),
        fullName: z
            .string({ error: "Full name is required." })
            .trim()
            .min(2, "Full name must contain at least 2 characters.")
            .max(200, "Full name is too long."),
        email: emailAddress,
        company: z
            .string({ error: "Company is required." })
            .trim()
            .min(1, "Company is required.")
            .max(200, "Company is too long."),
        password: activationPassword,
    })
    .strict();

export type SignupInput = z.infer<typeof signupSchema>;

export const forgotPasswordSchema = z
    .object({
        email: emailAddress,
    })
    .strict();

export const validatePasswordResetSchema = z
    .object({
        token: passwordResetToken,
    })
    .strict();

export const resetPasswordSchema = z
    .object({
        token: passwordResetToken,
        newPassword: activationPassword,
        confirmPassword: passwordConfirmation,
    })
    .strict()
    .superRefine((value, context) => {
        if (value.newPassword !== value.confirmPassword) {
            context.addIssue({
                code: "custom",
                path: ["confirmPassword"],
                message: "Password confirmation does not match.",
            });
        }
    });

export const changePasswordSchema = z
    .object({
        currentPassword: activationPassword,
        newPassword: activationPassword,
        confirmPassword: passwordConfirmation,
    })
    .strict()
    .superRefine((value, context) => {
        if (value.newPassword !== value.confirmPassword) {
            context.addIssue({
                code: "custom",
                path: ["confirmPassword"],
                message: "Password confirmation does not match.",
            });
        }
    });

export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type ValidatePasswordResetInput = z.infer<
    typeof validatePasswordResetSchema
>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
