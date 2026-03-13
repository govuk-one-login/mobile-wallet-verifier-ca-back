import { describe, it, expect, vi, beforeEach, MockInstance } from 'vitest';
import { getMockJwksConfig } from './config';
import '../../../tests/testUtils/matchers';

let consoleErrorSpy: MockInstance;

describe('getMockJwksConfig', () => {
  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, 'error');
  });

  it('should return success result when all required env vars are present', () => {
    const env = {
      FIREBASE_APPCHECK_JWKS_SECRET: 'mock-secret',
    };

    const result = getMockJwksConfig(env);

    expect(result.isError).toBe(false);
    if (!result.isError) {
      expect(result.value).toEqual({
        FIREBASE_APPCHECK_JWKS_SECRET: 'mock-secret',
      });
    }
  });

  it('should return error result when FIREBASE_APPCHECK_JWKS_SECRET is missing', () => {
    const env = {};

    const result = getMockJwksConfig(env);

    expect(result.isError).toBe(true);
    expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
      messageCode: 'MOBILE_CA_MOCK_JWKS_INVALID_CONFIG',
      data: {
        missingEnvironmentVariables: ['FIREBASE_APPCHECK_JWKS_SECRET'],
      },
    });
  });
});
