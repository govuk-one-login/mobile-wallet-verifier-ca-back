import {
  Config,
  getRequiredEnvironmentVariables,
} from '../common/config/environment';
import { logger } from '../common/logger/logger';
import { LogMessage } from '../common/logger/log-message';
import { Result, emptyFailure } from '../common/result/result';

const REQUIRED_ENVIRONMENT_VARIABLES = ['FIREBASE_JWKS_URI'] as const;

export type IssueReaderCertConfig = Config<
  (typeof REQUIRED_ENVIRONMENT_VARIABLES)[number]
>;

export function getIssueReaderCertConfig(
  env: NodeJS.ProcessEnv,
): Result<IssueReaderCertConfig, void> {
  const envVarsResult = getRequiredEnvironmentVariables(
    env,
    REQUIRED_ENVIRONMENT_VARIABLES,
  );

  if (envVarsResult.isError) {
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_CONFIG, {
      data: {
        missingEnvironmentVariables: envVarsResult.value.missingEnvVars,
      },
    });
    return emptyFailure();
  }

  return envVarsResult;
}
