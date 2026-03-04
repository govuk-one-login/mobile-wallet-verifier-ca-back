import {
  emptyFailure,
  emptySuccess,
  ErrorCategory,
  errorResult,
  Result,
  successResult,
} from '../common/result/result';
import { describe, it, beforeEach, expect, vi } from 'vitest';
import { verifyJwt, VerifyJwtDependencies } from './verify-jwt.ts';
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
  type JWTHeaderParameters,
} from 'jose';
import { JwksCache } from '../common/jwks/jwks-cache/types.ts';

describe('Verify JWT', () => {
  let result: Result<void, void>;
  let privateKey: CryptoKey;
  let publicJwk: JWK;
  let mockJwksCache: JwksCache;
  let dependencies: VerifyJwtDependencies;
  const mockJwksUrl = 'https://mockJwksUrl.com';
  const validExpectedClaims = {
    issuer: 'mockIssuer',
    audience: 'mockAudience',
    allowedAppId: ['mockSubject'],
  };
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

      it('Returns error result with client error', () => {
        expect(result).toEqual(
          errorResult({
            errorMessage: 'JWT signature or claims are invalid',
            errorCategory: ErrorCategory.CLIENT_ERROR,
          }),
        );
      });
    });

    describe('Given claim validation fails', () => {
      describe('Given issue claim is invalid', () => {
        beforeEach(async () => {
          const jwtWithInvalidIssuer = await createSignedJwt(privateKey, {
            issuer: 'invalidIssuer',
          });

          result = await verifyJwt(
            jwtWithInvalidIssuer,
            mockJwksUrl,
            validExpectedClaims,
            dependencies,
          );
        });

        it('Returns error result with client error', () => {
          expect(result).toEqual(
            errorResult({
              errorMessage: 'JWT signature or claims are invalid',
              errorCategory: ErrorCategory.CLIENT_ERROR,
            }),
          );
        });
      });

      describe('Given audience claim is invalid', () => {
        beforeEach(async () => {
          const jwtWithInvalidIssuer = await createSignedJwt(privateKey, {
            audience: 'invalidAudience',
          });

          result = await verifyJwt(
            jwtWithInvalidIssuer,
            mockJwksUrl,
            validExpectedClaims,
            dependencies,
          );
        });

        it('Returns error result with client error', () => {
          expect(result).toEqual(
            errorResult({
              errorMessage: 'JWT signature or claims are invalid',
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
    includeExp?: boolean;
  } = {},
): Promise<string> {
  const nowInSeconds = Math.floor(Date.now() / 1000);
  const protectedHeader: JWTHeaderParameters = {
    alg: options.alg ?? 'RS256',
    typ: 'JWT',
  };
  if (options.includeKid !== false) {
    protectedHeader.kid = 'mockKeyId';
  }

  let signedToken = new SignJWT({})
    .setProtectedHeader(protectedHeader)
    .setIssuer(options.issuer ?? 'mockIssuer')
    .setAudience(options.audience ?? 'mockAudience')
    .setSubject(options.subject ?? 'mockSubject')
    .setJti(options.tokenId ?? 'mockTokenJti')
    .setNotBefore(nowInSeconds - 5);

  if (options.includeExp !== false) {
    signedToken = signedToken.setExpirationTime(nowInSeconds + 120);
  }

  return signedToken.sign(privateKey);
}
