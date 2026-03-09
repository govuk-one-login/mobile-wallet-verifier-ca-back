import {
  emptyFailure,
  emptySuccess,
  ErrorCategory,
  errorResult,
  Result,
  successResult,
} from '../common/result/result';
import { describe, it, beforeEach, expect, vi, MockInstance } from 'vitest';
import { verifyJwt, VerifyJwtDependencies } from './verify-jwt.ts';
import {
  CompactSign,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
  type JWTHeaderParameters,
} from 'jose';
import { JwksCache } from '../common/jwks/jwks-cache/types.ts';
import '../../../tests/testUtils/matchers';

describe('Verify JWT', () => {
  let result: Result<void, void>;
  let privateKey: CryptoKey;
  let publicJwk: JWK;
  let mockJwksCache: JwksCache;
  let dependencies: VerifyJwtDependencies;
  const mockJwksUrl = 'https://mockJwksUrl.com';
  const validExpectedClaims = {
    issuer: 'mockIssuer',
    audience: ['mockAudience'],
    allowedAppId: ['mockSubject'],
  };
  let consoleErrorSpy: MockInstance;
  beforeEach(async () => {
    const generatedKeyPair = await generateKeyPair('RS256');
    privateKey = generatedKeyPair.privateKey;
    publicJwk = await exportJWK(generatedKeyPair.publicKey);
    publicJwk.kid = 'mockKeyId';
    publicJwk.alg = 'RS256';
    publicJwk.use = 'sig';
    mockJwksCache = {
      getJwks: vi.fn().mockResolvedValue(
        successResult({
          keys: [publicJwk],
        }),
      ),
    };
    dependencies = {
      jwksCache: mockJwksCache,
    };
    consoleErrorSpy = vi.spyOn(console, 'error');
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
          errorMessage: 'Invalid JWT format',
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
          errorMessage: 'JWT header does not include kid',
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
          errorMessage: 'JWT signature is invalid',
        });
      });

      it('Returns error result with client error', () => {
        expect(result).toEqual(
          errorResult({
            errorMessage: 'JWT signature is invalid',
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
          expectedErrorMessage: 'JWT claim(s) are invalid',
        },
        {
          scenario: 'Given aud claim is invalid',
          jwtConfig: {
            audience: 'invalidAudience',
          },
          expectedErrorMessage: 'JWT claim(s) are invalid',
        },
        {
          scenario: 'Given exp claim is expired',
          jwtConfig: {
            expOffsetSeconds: -10,
          },
          expectedErrorMessage: 'JWT expired',
        },
        {
          scenario: 'Given sub claim is not in the list of App Ids',
          jwtConfig: {
            subject: 'invalidAppId',
          },
          expectedErrorMessage:
            'JWT sub claim is not in the list of allowed App IDs',
        },
        {
          scenario: 'Given jti claim is invalid',
          jwtConfig: {
            tokenId: '',
          },
          expectedErrorMessage: 'JWT jti claim is missing',
        },
        {
          scenario: 'Given exp claim does not exist',
          jwtConfig: {
            includeExp: false,
          },
          expectedErrorMessage: 'JWT exp claim is missing',
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
            errorMessage: 'JWT algorithm is not allowed',
          });
        });

        it('Returns error result with client error', () => {
          expect(result).toEqual(
            errorResult({
              errorMessage: 'JWT algorithm is not allowed',
              errorCategory: ErrorCategory.CLIENT_ERROR,
            }),
          );
        });
      });

      describe('Given jwt is malformed', () => {
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
            errorMessage: 'JWT is malformed',
          });
        });

        it('Returns error result with client error', () => {
          expect(result).toEqual(
            errorResult({
              errorMessage: 'JWT is malformed',
              errorCategory: ErrorCategory.CLIENT_ERROR,
            }),
          );
        });
      });

      describe('Given jws is malformed', () => {
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
            errorMessage: 'JWT is malformed',
          });
        });

        it('Returns error result with client error', () => {
          expect(result).toEqual(
            errorResult({
              errorMessage: 'JWT is malformed',
              errorCategory: ErrorCategory.CLIENT_ERROR,
            }),
          );
        });
      });
    });
  });

  describe('WIP Happy path', () => {
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

async function createSignedJwt(
  privateKey: CryptoKey,
  options: {
    includeKid?: boolean;
    issuer?: string;
    audience?: string;
    subject?: string;
    tokenId?: string;
    alg?: string;
    kid?: string;
    includeExp?: boolean;
    expOffsetSeconds?: number;
  } = {},
): Promise<string> {
  const nowInSeconds = Math.floor(Date.now() / 1000);
  const protectedHeader: JWTHeaderParameters = {
    alg: options.alg ?? 'RS256',
    typ: 'JWT',
  };
  if (options.includeKid !== false) {
    protectedHeader.kid = options.kid ?? 'mockKeyId';
  }

  let signedToken = new SignJWT({})
    .setProtectedHeader(protectedHeader)
    .setIssuer(options.issuer ?? 'mockIssuer')
    .setAudience(options.audience ?? 'mockAudience')
    .setSubject(options.subject ?? 'mockSubject')
    .setJti(options.tokenId ?? 'mockTokenJti')
    .setNotBefore(nowInSeconds - 5);

  if (options.includeExp !== false) {
    signedToken = signedToken.setExpirationTime(
      nowInSeconds + (options.expOffsetSeconds ?? 120),
    );
  }

  return signedToken.sign(privateKey);
}

async function createSignedNonJsonJwt(privateKey: CryptoKey): Promise<string> {
  return new CompactSign(new TextEncoder().encode('not-json'))
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'JWT',
      kid: 'mockKeyId',
    })
    .sign(privateKey);
}

async function createMalformedJws(privateKey: CryptoKey): Promise<string> {
  const jwt = await createSignedJwt(privateKey);
  const [header, payload] = jwt.split('.');
  return `${header}.${payload}.not-base64!`;
}
