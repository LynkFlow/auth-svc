import argon2 from "argon2";

export const ARGON2_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
});

export interface PasswordPolicy {
  minimumLength: number;
  maximumLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumber: boolean;
  requireSymbol: boolean;
}

export function passwordPolicyViolations(
  password: string,
  policy: PasswordPolicy,
): string[] {
  const violations: string[] = [];
  const characterLength = Array.from(password).length;

  if (characterLength < policy.minimumLength) {
    violations.push(
      `Password must contain at least ${policy.minimumLength} characters.`,
    );
  }

  if (characterLength > policy.maximumLength) {
    violations.push(
      `Password must contain no more than ${policy.maximumLength} characters.`,
    );
  }

  if (policy.requireUppercase && !/\p{Lu}/u.test(password)) {
    violations.push("Password must contain an uppercase letter.");
  }

  if (policy.requireLowercase && !/\p{Ll}/u.test(password)) {
    violations.push("Password must contain a lowercase letter.");
  }

  if (policy.requireNumber && !/\p{N}/u.test(password)) {
    violations.push("Password must contain a number.");
  }

  if (policy.requireSymbol && !/[^\p{L}\p{N}\s]/u.test(password)) {
    violations.push("Password must contain a symbol.");
  }

  return violations;
}

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}
