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

export interface VerifyJwtDependencies {
  jwksCache: JwksCache;
}

const defaultDependencies: VerifyJwtDependencies = {
  jwksCache: InMemoryJwksCache.getSingletonInstance(),
};

export interface ExpectedClaims {
  issuer: string;
  audience: string;
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
      issuer: expectedClaims.issuer,
      audience: expectedClaims.audience,
    });
    payload = verifiedJwt.payload;
  } catch (error: unknown) {
    return errorResult({
      errorMessage: 'JWT signature or claims are invalid',
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  if (!expectedClaims.allowedAppId.includes(payload.sub as string)) {
    return errorResult({
      errorMessage: 'App ID is not in the list of allowed App IDs',
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  if (!payload.jti || !payload.jti.trim()) {
    return errorResult({
      errorMessage: 'JWT signature or claims are invalid',
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  // Jose jwtVerify function checks the type and expiration of exp claim automatically if it exists
  if (!payload.exp) {
    return errorResult({
      errorMessage: 'JWT signature or claims are invalid',
      errorCategory: ErrorCategory.CLIENT_ERROR,
    });
  }

  return emptySuccess();
}
