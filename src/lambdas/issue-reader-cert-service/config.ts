import {
  Config,
  getRequiredEnvironmentVariables,
} from '../common/config/environment';
import { logger } from '../common/logger/logger';
import { LogMessage } from '../common/logger/logMessage';
import { Result, emptyFailure } from '../common/result/result';

const REQUIRED_ENVIRONMENT_VARIABLES = ['FIREBASE_JWKS_URI'] as const;

export type IssuerReadCertServiceConfig = Config<
  (typeof REQUIRED_ENVIRONMENT_VARIABLES)[number]
>;

export function getActiveSessionConfig(
  env: NodeJS.ProcessEnv,
): Result<IssuerReadCertServiceConfig, void> {
  const envVarsResult = getRequiredEnvironmentVariables(
    env,
    REQUIRED_ENVIRONMENT_VARIABLES,
  );

  if (envVarsResult.isError) {
    logger.error(LogMessage.ISSUE_READER_CERT_SERVICE_INVALID_CONFIG, {
      data: { missingEnvironmentVariables: envVarsResult.value.missingEnvVars },
    });
    return emptyFailure();
  }

  return envVarsResult;
}
