import { describe, it, expect, vi, beforeEach, MockInstance } from 'vitest';
import { getGenerateMockIssueCertRequestConfig } from './config';
import '../../../tests/testUtils/matchers';

let consoleErrorSpy: MockInstance;

describe('getGenerateMockIssueCertRequestConfig', () => {
  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, 'error');
  });

  it('should return success result when all required env vars are present', () => {
    const env = {
      FIREBASE_APPCHECK_JWKS_SECRET: 'mock-firebase-secret',
      DEVICE_KEYS_SECRET: 'mock-device-secret',
      FIREBASE_JWKS_URI: 'https://firebaseappcheck.googleapis.com/v1/jwks',
    };

    const result = getGenerateMockIssueCertRequestConfig(env);

    expect(result.isError).toBe(false);
    if (!result.isError) {
      expect(result.value).toEqual({
        FIREBASE_APPCHECK_JWKS_SECRET: 'mock-firebase-secret',
        DEVICE_KEYS_SECRET: 'mock-device-secret',
        FIREBASE_JWKS_URI: 'https://firebaseappcheck.googleapis.com/v1/jwks',
      });
    }
  });

  it('should return error result when FIREBASE_APPCHECK_JWKS_SECRET is missing', () => {
    const env = {
      DEVICE_KEYS_SECRET: 'mock-device-secret',
      FIREBASE_JWKS_URI: 'https://firebaseappcheck.googleapis.com/v1/jwks',
    };

    const result = getGenerateMockIssueCertRequestConfig(env);

    expect(result.isError).toBe(true);
    expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
      messageCode: 'MOBILE_CA_MOCK_ISSUE_CERT_INVALID_CONFIG',
      data: {
        missingEnvironmentVariables: ['FIREBASE_APPCHECK_JWKS_SECRET'],
      },
    });
  });

  it('should return error result when DEVICE_KEYS_SECRET is missing', () => {
    const env = {
      FIREBASE_APPCHECK_JWKS_SECRET: 'mock-firebase-secret',
      FIREBASE_JWKS_URI: 'https://firebaseappcheck.googleapis.com/v1/jwks',
    };

    const result = getGenerateMockIssueCertRequestConfig(env);

    expect(result.isError).toBe(true);
    expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
      messageCode: 'MOBILE_CA_MOCK_ISSUE_CERT_INVALID_CONFIG',
      data: {
        missingEnvironmentVariables: ['DEVICE_KEYS_SECRET'],
      },
    });
  });

  it('should return error result when FIREBASE_JWKS_URI is missing', () => {
    const env = {
      FIREBASE_APPCHECK_JWKS_SECRET: 'mock-firebase-secret',
      DEVICE_KEYS_SECRET: 'mock-device-secret',
    };

    const result = getGenerateMockIssueCertRequestConfig(env);

    expect(result.isError).toBe(true);
    expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
      messageCode: 'MOBILE_CA_MOCK_ISSUE_CERT_INVALID_CONFIG',
      data: {
        missingEnvironmentVariables: ['FIREBASE_JWKS_URI'],
      },
    });
  });
});
