import {
  emptySuccess,
  ErrorCategory,
  errorResult,
  Result,
} from '../common/result/result.ts';
import {
  createLocalJWKSet,
  decodeProtectedHeader,
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
      // Add alg here
      audience: expectedClaims.audience, // what is the type of audience? does this need to change?
      issuer: expectedClaims.issuer,
    });
    payload = verifiedJwt.payload;
  } catch (error: unknown) {
    return errorResult({
      errorMessage: 'JWT signature or claims are invalid',
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
    const errorMessage = 'JWT jti claim is missing'
    logger.error(LogMessage.JWT_VERIFICATION_FAILURE, {
      errorMessage,
    });
    return errorResult({
      errorMessage,
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  // Jose jwtVerify function checks the type and expiration of exp claim automatically if it exists
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
