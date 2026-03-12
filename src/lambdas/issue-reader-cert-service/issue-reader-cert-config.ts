import { getRequiredEnvironmentVariables } from '../common/config/environment';
import { logger } from '../common/logger/logger';
import { LogMessage } from '../common/logger/log-message';
import { Result, emptyFailure, successResult } from '../common/result/result';

const REQUIRED_ENVIRONMENT_VARIABLES = [
  'ALGORITHM',
  'ALLOWED_APP_IDS',
  'AUDIENCE',
  'FIREBASE_JWKS_URI',
  'ISSUER',
] as const;

export type IssueReaderCertConfig = {
  ALGORITHM: string;
  ALLOWED_APP_IDS: string[];
  AUDIENCE: string[];
  ISSUER: string;
  FIREBASE_JWKS_URI: string;
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

  const parsedAllowedAppIds = parseJsonStringArray(
    envVarsResult.value.ALLOWED_APP_IDS,
  );

  if (!parsedAllowedAppIds) {
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_CONFIG, {
      errorMessage: 'ALLOWED_APP_IDS must be a JSON array of strings',
    });
    return emptyFailure();
  }

  const parsedAudience = parseJsonStringArray(envVarsResult.value.AUDIENCE);
  if (!parsedAudience) {
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_CONFIG, {
      errorMessage: 'AUDIENCE must be a JSON array of strings',
    });
    return emptyFailure();
  }

  return successResult({
    ...envVarsResult.value, // Spread all basic string envVars
    ALLOWED_APP_IDS: parsedAllowedAppIds,
    AUDIENCE: parsedAudience,
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
