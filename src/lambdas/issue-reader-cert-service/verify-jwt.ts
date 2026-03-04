import {
  emptySuccess,
  ErrorCategory,
  errorResult, FailureWithValue,
  Result,
} from '../common/result/result.ts';
import { decodeProtectedHeader } from 'jose';
import { JwksCache } from '../common/jwks/jwks-cache/types.ts';
import { InMemoryJwksCache } from '../common/jwks/jwks-cache/jwks-cache.ts';

export interface VerifyJwtDependencies {
  jwksCache: JwksCache;
}

const defaultDependencies: VerifyJwtDependencies = {
  jwksCache: InMemoryJwksCache.getSingletonInstance(),
};
export async function verifyJwt(
  jwt: string,
  dependencies: VerifyJwtDependencies = defaultDependencies,
  jwksUrl: string
): Promise<Result<void>> {
  // const jwt = "mockHeader.mockPayload.mockSignature";

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

  const jwksResult = await dependencies.jwksCache.getJwks(jwksUrl, header.kid)

  return emptySuccess();
}
