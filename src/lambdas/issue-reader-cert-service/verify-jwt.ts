import {
  emptySuccess,
  ErrorCategory,
  errorResult,
  Result,
} from '../common/result/result.ts';
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  errors,
  JWTPayload,
  jwtVerify,
} from 'jose';
import { JwksCache } from '../common/jwks/jwks-cache/types.ts';
import { InMemoryJwksCache } from '../common/jwks/jwks-cache/jwks-cache.ts';
import { logger } from '../common/logger/logger.ts';
import { LogMessage } from '../common/logger/log-message.ts';

export interface VerifyJwtDependencies {
  jwksCache: JwksCache;
}

const defaultDependencies: VerifyJwtDependencies = {
  jwksCache: InMemoryJwksCache.getSingletonInstance(),
};

export interface ExpectedClaims {
  issuer: string;
  audience: string[];
  allowedAppId: string[];
}
export async function verifyJwt(
  jwt: string,
  jwksUrl: string,
  expectedClaims: ExpectedClaims,
  dependencies: VerifyJwtDependencies = defaultDependencies,
): Promise<Result<void, void>> {
  if (jwt.split('.').length !== 3) {
    return errorResult({
      errorMessage: 'Invalid JWT format',
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  const header = decodeProtectedHeader(jwt);

  if (!header.kid || !header.kid.trim()) {
    return errorResult({
      errorMessage: 'JWT header does not include kid',
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  const jwksResult = await dependencies.jwksCache.getJwks(jwksUrl, header.kid);
  if (jwksResult.isError) {
    return errorResult({
      errorMessage: 'Unexpected error when fetching JWKS',
      errorCategory: ErrorCategory.SERVER_ERROR,
    });
  }

  const jwks = jwksResult.value;

  const localJwks = createLocalJWKSet({
    keys: jwks.keys,
  });

  let payload: JWTPayload;
  try {
    const verifiedJwt = await jwtVerify(jwt, localJwks, {
      algorithms: ['RS256'],
      audience: expectedClaims.audience,
      issuer: expectedClaims.issuer,
    });
    payload = verifiedJwt.payload;
  } catch (error: unknown) {
    if (error instanceof errors.JWTClaimValidationFailed) {
      return errorResult({
        errorMessage: 'JWT claims are invalid',
        errorCategory: ErrorCategory.CLIENT_ERROR,
      });
    }

    if (error instanceof errors.JWTExpired) {
      return errorResult({
        errorMessage: 'JWT expired',
        errorCategory: ErrorCategory.CLIENT_ERROR,
      });
    }

    if (error instanceof errors.JWSSignatureVerificationFailed) {
      return errorResult({
        errorMessage: 'JWT signature is invalid',
        errorCategory: ErrorCategory.CLIENT_ERROR,
      });
    }

    if (error instanceof errors.JOSEAlgNotAllowed) {
      return errorResult({
        errorMessage: 'JWT algorithm is not allowed',
        errorCategory: ErrorCategory.CLIENT_ERROR,
      });
    }

    if (
      error instanceof errors.JWTInvalid ||
      error instanceof errors.JWSInvalid
    ) {
      return errorResult({
        errorMessage: 'JWT is malformed',
        errorCategory: ErrorCategory.CLIENT_ERROR,
      });
    }

    return errorResult({
      errorMessage: 'JWT signature verification failed',
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  if (!payload.sub || !expectedClaims.allowedAppId.includes(payload.sub)) {
    const errorMessage = 'JWT sub is not in the list of allowed App IDs';
    logger.error(LogMessage.JWT_VERIFICATION_FAILURE, {
      errorMessage,
    });
    return errorResult({
      errorMessage,
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  if (!payload.jti || !payload.jti.trim()) {
    const errorMessage = 'JWT jti claim is missing';
    logger.error(LogMessage.JWT_VERIFICATION_FAILURE, {
      errorMessage,
    });
    return errorResult({
      errorMessage,
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  if (!payload.exp) {
    const errorMessage = 'JWT exp claim is missing';
    logger.error(LogMessage.JWT_VERIFICATION_FAILURE, {
      errorMessage,
    });
    return errorResult({
      errorMessage,
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  return emptySuccess();
}

export interface TokenReplayCache {
  consume(tokenId: string, tokenExpiryEpochSeconds: number): boolean;
}

export class InMemoryTokenReplayCache implements TokenReplayCache {
  private static INSTANCE: TokenReplayCache;
  private readonly tokenExpiriesById = new Map<string, number>();

  static getSingletonInstance(
    nowInMillis: () => number = Date.now,
  ): TokenReplayCache {
    if (!this.INSTANCE)
      this.INSTANCE = new InMemoryTokenReplayCache(nowInMillis);
    return this.INSTANCE;
  }

  constructor(private readonly nowInMillis: () => number = Date.now) {}

  consume(tokenId: string, tokenExpiryEpochSeconds: number): boolean {
    this.deleteExpiredEntries();

    const now = this.nowInMillis();
    const existingTokenExpiry = this.tokenExpiriesById.get(tokenId);
    if (existingTokenExpiry !== undefined && existingTokenExpiry > now) {
      return false;
    }

    this.tokenExpiriesById.set(tokenId, tokenExpiryEpochSeconds * 1000);
    return true;
  }

  private deleteExpiredEntries() {
    const now = this.nowInMillis();
    for (const [tokenId, expiry] of this.tokenExpiriesById.entries()) {
      if (expiry <= now) {
        this.tokenExpiriesById.delete(tokenId);
      }
    }
  }
}
