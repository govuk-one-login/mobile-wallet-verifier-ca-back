import { ErrorCategory, errorResult, Result } from '../common/result/result';
import { describe, it, beforeEach, expect } from 'vitest';
import { verifyJwt } from './verify-jwt.ts';
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
  type JWTHeaderParameters,
} from 'jose';

describe('Verify JWT', () => {
  let result: Result<void, void>;
  let privateKey: CryptoKey;
  let publicJwk: JWK;
  beforeEach(async () => {
    const generatedKeyPair = await generateKeyPair('RS256');
    privateKey = generatedKeyPair.privateKey;
    publicJwk = await exportJWK(generatedKeyPair.publicKey);
    publicJwk.kid = 'mockKeyId';
    publicJwk.alg = 'RS256';
    publicJwk.use = 'sig';
  });
  describe('Given JWT is in invalid compact JWT format', () => {
    beforeEach(async () => {
      result = verifyJwt('invalidFormatJwt');
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
      result = verifyJwt(jwtWithoutKid);
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
});

async function createSignedJwt(
  privateKey: CryptoKey,
  options: {
    includeKid?: boolean;
    issuer?: string;
    audience?: string;
    subject?: string;
    tokenId?: string;
    includeExp?: boolean;
  } = {},
): Promise<string> {
  const nowInSeconds = Math.floor(Date.now() / 1000);
  const protectedHeader: JWTHeaderParameters = {
    alg: 'RS256',
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
