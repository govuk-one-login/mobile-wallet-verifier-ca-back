import { Result } from './types/Result';
import { Config, getRequiredEnvironmentVariables, MissingEnvVarError } from './utils/environment';

const REQUIRED_ENVIRONMENT_VARIABLES = [
  'PLATFORM_CA_ARN_PARAMETER',
  'PLATFORM_CA_ISSUER_ALTERNATIVE_NAME',
  'VERIFIER_KEY_ID',
  'VERIFIER_KEY_BUCKET',
  'VERIFIER_KEY_VALIDITY_PERIOD',
  'VERIFIER_KEY_COMMON_NAME',
  'VERIFIER_KEY_COUNTRY_NAME',
  'ROOT_CERTIFICATE'
  // 'VERIFIER_PRIVATE_KEY'
] as const;

export type IssueVerifierCertificateConfig = Config<(typeof REQUIRED_ENVIRONMENT_VARIABLES)[number]>;

export function getConfigFromEnvironment(
  env: NodeJS.ProcessEnv,
): Result<IssueVerifierCertificateConfig, MissingEnvVarError> {
  const result = getRequiredEnvironmentVariables(env, REQUIRED_ENVIRONMENT_VARIABLES);
  if (result.isError) {
    // Print missing variable(s) for debugging
    if (result.error && result.error.missingEnvVars) {
      // eslint-disable-next-line no-console
      console.error('Missing required environment variable(s):', result.error.missingEnvVars);
    } else {
      // eslint-disable-next-line no-console
      console.error('Config error:', result.error);
    }
  }
  return result;
}
