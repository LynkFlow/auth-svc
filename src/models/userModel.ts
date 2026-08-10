export const ACCOUNT_STATUS = Object.freeze({
    PENDING_ACTIVATION: "pending_activation",
    ACTIVE: "active",
    INACTIVE: "inactive",
    SUSPENDED: "suspended",
} as const);

export type AccountStatus =
    (typeof ACCOUNT_STATUS)[keyof typeof ACCOUNT_STATUS];

export interface UserRecord {
    id: string;
    email: string;
    passwordHash: string | null;
    accountStatus: AccountStatus;
    failedLoginAttempts: number;
    lockedUntil: Date | null;
    activatedAt: Date | null;
    lastLoginAt: Date | null;
    roleCode: string;
    roleName: string;
    permissions: string[];
}

export interface PublicUser {
    id: string;
    email: string;
    role: {
        code: string;
        name: string;
    };
    permissions: string[];
    lastLoginAt: string | null;
}

export function toPublicUser(user: UserRecord): PublicUser {
    return {
        id: user.id,
        email: user.email,
        role: {
            code: user.roleCode,
            name: user.roleName,
        },
        permissions: user.permissions,
        lastLoginAt: user.lastLoginAt
            ? new Date(user.lastLoginAt).toISOString()
            : null,
    };
}
