import { CamelCasePlugin, Kysely, PostgresDialect } from "kysely";
import pool from "./db/pool.js";
import type { Database } from "./db/schema.js";
import logger from "./logging/logger.js";
import { HealthRepository } from "./repositories/HealthRepository.js";
import { HealthService } from "./services/HealthService.js";
import { HealthController } from "./controllers/HealthController.js";
import { UserRepository } from "./repositories/UserRepository.js";
import { SessionRepository } from "./repositories/SessionRepository.js";
import { SettingsRepository } from "./repositories/SettingsRepository.js";
import { ActivationRepository } from "./repositories/ActivationRepository.js";
import { PasswordResetRepository } from "./repositories/PasswordResetRepository.js";
import { OutboxRepository } from "./repositories/OutboxRepository.js";
import { TokenService } from "./services/TokenService.js";
import { AuthService } from "./services/AuthService.js";
import { ActivationService } from "./services/ActivationService.js";
import { PasswordManagementService } from "./services/PasswordManagementService.js";
import { SignupService } from "./services/SignupService.js";
import { AuthController } from "./controllers/AuthController.js";
import { AuthGuard } from "./guards/AuthGuard.js";
import { AuditLogRepository } from "./audit/AuditLogRepository.js";
import { AuditLogService } from "./audit/AuditLogService.js";

const db = new Kysely<Database>({
  dialect: new PostgresDialect({ pool }),
  plugins: [new CamelCasePlugin()],
});

/**
 * The one place the real dependency graph gets wired with `new`. Every
 * class elsewhere receives its dependencies as constructor arguments and
 * never constructs its own collaborators -- see backend-conventions.md.
 * Tests never touch this file for unit-level assertions (they construct
 * the one or two classes under test directly with hand-written
 * mocks/stubs) but the DB-backed integration tests under test/ do call
 * buildContainer() to get real, wired instances against the real pool --
 * exactly the composition root's job, just reused instead of duplicated.
 */
export interface Container {
  healthController: HealthController;
  authController: AuthController;
  authGuard: AuthGuard;
  tokenService: TokenService;
  authService: AuthService;
  activationService: ActivationService;
  passwordManagementService: PasswordManagementService;
  signupService: SignupService;
  userRepository: UserRepository;
  sessionRepository: SessionRepository;
  settingsRepository: SettingsRepository;
  activationRepository: ActivationRepository;
  passwordResetRepository: PasswordResetRepository;
  outboxRepository: OutboxRepository;
  auditLogService: AuditLogService;
}

export function buildContainer(): Container {
  const healthRepository = new HealthRepository(db);
  const healthService = new HealthService(healthRepository);
  const healthController = new HealthController(healthService);

  const userRepository = new UserRepository(db);
  const sessionRepository = new SessionRepository(db);
  const settingsRepository = new SettingsRepository(db);
  const activationRepository = new ActivationRepository(db);
  const passwordResetRepository = new PasswordResetRepository(db);
  const outboxRepository = new OutboxRepository(db);
  const auditLogRepository = new AuditLogRepository(db);

  const tokenService = new TokenService();
  const authService = new AuthService(
    db,
    userRepository,
    sessionRepository,
    settingsRepository,
    tokenService,
  );
  const activationService = new ActivationService(
    db,
    activationRepository,
    outboxRepository,
    settingsRepository,
    userRepository,
  );
  const passwordManagementService = new PasswordManagementService(
    db,
    outboxRepository,
    passwordResetRepository,
    sessionRepository,
    settingsRepository,
    userRepository,
  );
  const signupService = new SignupService(
    db,
    activationRepository,
    outboxRepository,
    settingsRepository,
    userRepository,
  );
  const auditLogService = new AuditLogService(auditLogRepository, logger);

  const authGuard = new AuthGuard(tokenService, sessionRepository);
  const authController = new AuthController(
    authService,
    activationService,
    passwordManagementService,
    signupService,
    tokenService,
    auditLogService,
  );

  return {
    healthController,
    authController,
    authGuard,
    tokenService,
    authService,
    activationService,
    passwordManagementService,
    signupService,
    userRepository,
    sessionRepository,
    settingsRepository,
    activationRepository,
    passwordResetRepository,
    outboxRepository,
    auditLogService,
  };
}
