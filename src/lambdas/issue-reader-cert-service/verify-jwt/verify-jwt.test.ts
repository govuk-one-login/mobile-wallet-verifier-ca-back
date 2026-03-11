import {
  emptyFailure,
  emptySuccess,
  ErrorCategory,
  errorResult,
  Result,
  successResult,
} from '../../common/result/result.ts';
import {
  describe,
  it,
  beforeEach,
  expect,
  vi,
  MockInstance,
  afterEach,
} from 'vitest';
import { verifyJwt, VerifyJwtDependencies } from './verify-jwt.ts';
import { exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { JwksCache } from '../../common/jwks/jwks-cache/types.ts';
import '../../../../tests/testUtils/matchers.ts';
import { InMemoryJwtReplayCache } from './jwt-replay-cache.ts';
import {
  createKeyPair,
  createJwtWithInvalidProtectedHeader,
  createSignedJwt,
  createSignedNonJsonJwt,
  createMalformedJws,
} from '../../../../tests/testUtils/create-signed-jwt.ts';

describe('Verify JWT', () => {
  let result: Result<void>;
  let privateKey: CryptoKey;
  let publicJwk: JWK;
  let mockJwksCache: JwksCache;
  let dependencies: VerifyJwtDependencies;
  const mockJwksUrl = 'https://mockJwksUrl.com';
  const validExpectedClaims = {
    algorithm: 'RS256',
    allowedAppIds: ['mockSubject'],
    audience: ['mockAudience'],
    issuer: 'mockIssuer',
  };
  let consoleErrorSpy: MockInstance;

  beforeEach(async () => {
    ({ privateKey, publicJwk } = await createKeyPair());
    mockJwksCache = {
      getJwks: vi.fn().mockResolvedValue(
        successResult({
          keys: [publicJwk],
        }),
      ),
    };
    dependencies = {
      jwksCache: mockJwksCache,
      jwtReplayCache: new InMemoryJwtReplayCache(),
    };
    consoleErrorSpy = vi.spyOn(console, 'error');
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Given JWT is in invalid compact JWT format', () => {
    beforeEach(async () => {
      result = await verifyJwt(
        'invalidFormatJwt',
        mockJwksUrl,
        validExpectedClaims,
        dependencies,
      );
    });

    it('Returns error result with client error', () => {
      expect(result).toEqual(
        errorResult({
          errorMessage: 'Invalid App Check JWT format',
          errorCategory: ErrorCategory.CLIENT_ERROR,
        }),
      );
    });
  });

  describe('Given JWT header is invalid', () => {
    beforeEach(async () => {
      const jwtWithInvalidProtectedHeader =
        await createJwtWithInvalidProtectedHeader(privateKey);
      result = await verifyJwt(
        jwtWithInvalidProtectedHeader,
        mockJwksUrl,
        validExpectedClaims,
        dependencies,
      );
    });

    it('Logs error', () => {
      expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
        messageCode: 'MOBILE_CA_JWT_VERIFICATION_FAILURE',
        errorMessage: 'Invalid App Check JWT header format',
      });
    });

    it('Returns error result with client error', () => {
      expect(result).toEqual(
        errorResult({
          errorMessage: 'Invalid App Check JWT header format',
          errorCategory: ErrorCategory.CLIENT_ERROR,
        }),
      );
    });
  });

  describe('Given JWT header does not include kid', () => {
    beforeEach(async () => {
      const jwtWithoutKid = await createSignedJwt(privateKey, {
        includeKid: false,
      });
      result = await verifyJwt(
        jwtWithoutKid,
        mockJwksUrl,
        validExpectedClaims,
        dependencies,
      );
    });

    it('Returns error result with client error', () => {
      expect(result).toEqual(
        errorResult({
          errorMessage: 'App Check JWT header does not include kid',
          errorCategory: ErrorCategory.CLIENT_ERROR,
        }),
      );
    });
  });

  describe('Given JWKS retrieval fails', () => {
    beforeEach(async () => {
      const jwt = await createSignedJwt(privateKey);
      dependencies.jwksCache.getJwks = vi
        .fn()
        .mockResolvedValue(emptyFailure());
      result = await verifyJwt(
        jwt,
        mockJwksUrl,
        validExpectedClaims,
        dependencies,
      );
    });

    it('Returns error result with server error', () => {
      expect(result).toEqual(
        errorResult({
          errorMessage: 'Unexpected error when fetching JWKS',
          errorCategory: ErrorCategory.SERVER_ERROR,
        }),
      );
    });
  });

  describe('Given JWT verification fails', () => {
    describe('Given signature verification fails', () => {
      beforeEach(async () => {
        const differentKeyPair = await generateKeyPair('RS256');
        const jwtWithInvalidSignature = await createSignedJwt(
          differentKeyPair.privateKey,
        );

        result = await verifyJwt(
          jwtWithInvalidSignature,
          mockJwksUrl,
          validExpectedClaims,
          dependencies,
        );
      });

      it('Logs error', async () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_JWT_VERIFICATION_FAILURE',
          errorMessage: 'App Check JWT signature is invalid',
        });
      });

      it('Returns error result with client error', () => {
        expect(result).toEqual(
          errorResult({
            errorMessage: 'App Check JWT signature is invalid',
            errorCategory: ErrorCategory.CLIENT_ERROR,
          }),
        );
      });
    });

    describe('Given claim validation fails', () => {
      describe.each([
        {
          scenario: 'Given iss claim is invalid',
          jwtConfig: {
            issuer: 'invalidIssuer',
          },
          expectedErrorMessage: 'App Check JWT iss claim is invalid',
        },
        {
          scenario: 'Given aud claim is invalid',
          jwtConfig: {
            audience: 'invalidAudience',
          },
          expectedErrorMessage: 'App Check JWT aud claim is invalid',
        },
        {
          scenario: 'Given nbf claim is in the future',
          jwtConfig: {
            nbfOffsetSeconds: 120,
          },
          expectedErrorMessage: 'App Check JWT nbf claim is invalid',
        },
        {
          scenario: 'Given exp claim is expired',
          jwtConfig: {
            expOffsetSeconds: -10,
          },
          expectedErrorMessage: 'App Check JWT expired',
        },
        {
          scenario: 'Given exp claim does not exist',
          jwtConfig: {
            includeExp: false,
          },
          expectedErrorMessage: 'App Check JWT exp claim is missing',
        },
        {
          scenario: 'Given sub claim is not in the list of App Ids',
          jwtConfig: {
            subject: 'App Check invalidAppId',
          },
          expectedErrorMessage:
            'App Check JWT sub claim is not in the list of allowed App IDs',
        },
        {
          scenario: 'Given jti claim is invalid',
          jwtConfig: {
            jti: '',
          },
          expectedErrorMessage: 'App Check JWT jti claim is missing',
        },
        {
          scenario:
            'Given other verification failure happens that is not explicitly handled',
          jwtConfig: {
            kid: 'differentKid',
          },
          expectedErrorMessage: 'App Check JWT verification failed',
        },
      ])('$scenario', ({ jwtConfig, expectedErrorMessage }) => {
        beforeEach(async () => {
          const jwtWithInvalidIssuer = await createSignedJwt(
            privateKey,
            jwtConfig,
          );

          result = await verifyJwt(
            jwtWithInvalidIssuer,
            mockJwksUrl,
            validExpectedClaims,
            dependencies,
          );
        });

        it('Logs error', async () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_JWT_VERIFICATION_FAILURE',
            errorMessage: expectedErrorMessage,
          });
        });

        it('Returns error result with client error', () => {
          expect(result).toEqual(
            errorResult({
              errorMessage: expectedErrorMessage,
              errorCategory: ErrorCategory.CLIENT_ERROR,
            }),
          );
        });
      });

      describe('Given jwt algorithm is not allowed', () => {
        beforeEach(async () => {
          const generatedPs256KeyPair = await generateKeyPair('PS256');
          const ps256PublicJwk = await exportJWK(
            generatedPs256KeyPair.publicKey,
          );
          ps256PublicJwk.kid = 'mockPs256KeyId';
          ps256PublicJwk.alg = 'PS256';
          ps256PublicJwk.use = 'sig';

          dependencies.jwksCache.getJwks = vi.fn().mockResolvedValue(
            successResult({
              keys: [ps256PublicJwk],
            }),
          );

          const jwtWithDisallowedAlg = await createSignedJwt(
            generatedPs256KeyPair.privateKey,
            {
              alg: 'PS256',
              kid: 'mockPs256KeyId',
            },
          );

          result = await verifyJwt(
            jwtWithDisallowedAlg,
            mockJwksUrl,
            validExpectedClaims,
            dependencies,
          );
        });

        it('Logs error', async () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_JWT_VERIFICATION_FAILURE',
            errorMessage: 'App Check JWT algorithm is not allowed',
          });
        });

        it('Returns error result with client error', () => {
          expect(result).toEqual(
            errorResult({
              errorMessage: 'App Check JWT algorithm is not allowed',
              errorCategory: ErrorCategory.CLIENT_ERROR,
            }),
          );
        });
      });

      describe('Given JWT is malformed', () => {
        beforeEach(async () => {
          const jwtWithNonJsonPayload =
            await createSignedNonJsonJwt(privateKey);

          result = await verifyJwt(
            jwtWithNonJsonPayload,
            mockJwksUrl,
            validExpectedClaims,
            dependencies,
          );
        });

        it('Logs error', async () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_JWT_VERIFICATION_FAILURE',
            errorMessage: 'App Check JWT is malformed',
          });
        });

        it('Returns error result with client error', () => {
          expect(result).toEqual(
            errorResult({
              errorMessage: 'App Check JWT is malformed',
              errorCategory: ErrorCategory.CLIENT_ERROR,
            }),
          );
        });
      });

      describe('Given JWS is malformed', () => {
        beforeEach(async () => {
          const malformedJws = await createMalformedJws(privateKey);

          result = await verifyJwt(
            malformedJws,
            mockJwksUrl,
            validExpectedClaims,
            dependencies,
          );
        });

        it('Logs error', async () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_JWT_VERIFICATION_FAILURE',
            errorMessage: 'App Check JWT is malformed',
          });
        });

        it('Returns error result with client error', () => {
          expect(result).toEqual(
            errorResult({
              errorMessage: 'App Check JWT is malformed',
              errorCategory: ErrorCategory.CLIENT_ERROR,
            }),
          );
        });
      });
    });
  });

  describe('Given JWT replay is detected', () => {
    beforeEach(async () => {
      const jwt = await createSignedJwt(privateKey, {
        jti: 'mockJti',
      });
      await verifyJwt(jwt, mockJwksUrl, validExpectedClaims, dependencies);
      result = await verifyJwt(
        jwt,
        mockJwksUrl,
        validExpectedClaims,
        dependencies,
      );
    });

    it('Logs error', () => {
      expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
        messageCode: 'MOBILE_CA_JWT_VERIFICATION_FAILURE',
        errorMessage: 'App Check JWT replay detected',
      });
    });

    it('Returns error result with client error', () => {
      expect(result).toEqual(
        errorResult({
          errorMessage: 'App Check JWT replay detected',
          errorCategory: ErrorCategory.CLIENT_ERROR,
        }),
      );
    });
  });

  describe('Given JWT is valid', () => {
    beforeEach(async () => {
      const jwt = await createSignedJwt(privateKey);
      result = await verifyJwt(
        jwt,
        mockJwksUrl,
        validExpectedClaims,
        dependencies,
      );
    });

    it('Returns empty success', () => {
      expect(result).toEqual(emptySuccess());
    });
  });
});
