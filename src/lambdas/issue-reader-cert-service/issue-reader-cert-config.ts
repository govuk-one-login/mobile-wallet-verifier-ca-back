import {
  Config,
  getRequiredEnvironmentVariables,
} from '../common/config/environment';
import { logger } from '../common/logger/logger';
import { LogMessage } from '../common/logger/log-message';
import { Result, emptyFailure, successResult } from '../common/result/result';

const REQUIRED_ENVIRONMENT_VARIABLES = [
  'FIREBASE_JWKS_URI',
  'ISSUER',
  'AUDIENCE',
  'ALLOWED_APP_ID',
] as const;

type RawIssueReaderCertConfig = Config<
  (typeof REQUIRED_ENVIRONMENT_VARIABLES)[number]
>;

export type IssueReaderCertConfig = Omit<
  RawIssueReaderCertConfig,
  'ALLOWED_APP_ID'
> & {
  ALLOWED_APP_ID: string[];
};

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

  if (!isValidUrl(envVarsResult.value.FIREBASE_JWKS_URI)) {
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_CONFIG, {
      errorMessage: 'FIREBASE_JWKS_URI is not a valid URL',
    });
    return emptyFailure();
  }

  const parsedAllowedAppId = parseJsonStringArray(
    envVarsResult.value.ALLOWED_APP_ID,
  );
  if (!parsedAllowedAppId) {
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_CONFIG, {
      errorMessage: 'ALLOWED_APP_ID must be a JSON array of strings',
    });
    return emptyFailure();
  }

  return successResult({
    ...envVarsResult.value,
    ALLOWED_APP_ID: parsedAllowedAppId,
  });
}

const isValidUrl = (url: string): boolean => {
  try {
    new URL(url);
  } catch {
    return false;
  }
  return true;
};

function parseJsonStringArray(value: string): string[] | null {
  let parsedValue: unknown;
  try {
    parsedValue = JSON.parse(value);
  } catch {
    return null;
  }

  if (
    !Array.isArray(parsedValue) ||
    !parsedValue.every((item) => typeof item === 'string')
  ) {
    return null;
  }
  return parsedValue;
}
