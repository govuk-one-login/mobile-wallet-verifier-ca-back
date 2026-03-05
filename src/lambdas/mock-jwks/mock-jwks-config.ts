import {
  Config,
  getRequiredEnvironmentVariables,
} from '../common/config/environment';
import { logger } from '../common/logger/logger';
import { LogMessage } from '../common/logger/log-message';
import { Result, emptyFailure } from '../common/result/result';

const REQUIRED_ENVIRONMENT_VARIABLES = [
  'FIREBASE_APPCHECK_JWKS_SECRET',
] as const;

export type MockJwksConfig = Config<
  (typeof REQUIRED_ENVIRONMENT_VARIABLES)[number]
>;

export function getMockJwksConfig(
  env: NodeJS.ProcessEnv,
): Result<MockJwksConfig, void> {
  const envVarsResult = getRequiredEnvironmentVariables(
    env,
    REQUIRED_ENVIRONMENT_VARIABLES,
  );

  if (envVarsResult.isError) {
    logger.error(LogMessage.MOCK_JWKS_INVALID_CONFIG, {
      data: {
        missingEnvironmentVariables: envVarsResult.value.missingEnvVars,
      },
    });
    return emptyFailure();
  }

  return envVarsResult;
}
