import {
  Result,
  errorResult,
  successResult,
  SuccessWithValue,
} from '../result/result';

export type MissingEnvVarError = {
  missingEnvVars: string[];
};

export type Config<T extends string> = {
  [key in T]: string;
};

export const getRequiredEnvironmentVariables = <T extends string>(
  env: NodeJS.ProcessEnv | Record<string, string | string[] | undefined>,
  requiredEnvironmentVariables: readonly T[],
): Result<Config<T>, MissingEnvVarError> => {
  const config: Partial<Config<T>> = requiredEnvironmentVariables.reduce(
    (partialConfig: Partial<Config<T>>, key) => {
      const value = env[key];
      if (Array.isArray(value)) {
        partialConfig[key] = value.join(',') as Config<T>[T];
      } else {
        partialConfig[key] = value as Config<T>[T];
      }
      return partialConfig;
    },
    {},
  );

  const missingEnvironmentVariables = requiredEnvironmentVariables.filter(
    (key) => !config[key],
  );

  if (missingEnvironmentVariables.length >= 1) {
    return errorResult({
      missingEnvVars: missingEnvironmentVariables,
    });
  }
  return successResult(config) as SuccessWithValue<Config<T>>;
};
