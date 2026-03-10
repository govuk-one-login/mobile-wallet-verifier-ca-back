import {
  emptySuccess,
  ErrorCategory,
  errorResult,
  Result,
} from '../../common/result/result.ts';
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  errors,
  JWTPayload,
  jwtVerify,
} from 'jose';
import { JwksCache } from '../../common/jwks/jwks-cache/types.ts';
import { InMemoryJwksCache } from '../../common/jwks/jwks-cache/jwks-cache.ts';
import { logger } from '../../common/logger/logger.ts';
import { LogMessage } from '../../common/logger/log-message.ts';
import { InMemoryJwtReplayCache, JwtReplayCache } from './jwt-replay-cache.ts';

export interface VerifyJwtDependencies {
  jwksCache: JwksCache;
  jwtReplayCache: JwtReplayCache;
}

const defaultDependencies: VerifyJwtDependencies = {
  jwksCache: InMemoryJwksCache.getSingletonInstance(),
  jwtReplayCache: InMemoryJwtReplayCache.getSingletonInstance(),
};

export interface ExpectedJwtData {
  algorithm: string;
  allowedAppId: string[];
  audience: string[];
  issuer: string;
}

export async function verifyJwt(
  jwt: string,
  jwksUrl: string,
  expectedJwtData: ExpectedJwtData,
  dependencies: VerifyJwtDependencies = defaultDependencies,
): Promise<Result<void>> {
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

  const getJwksResult = await dependencies.jwksCache.getJwks(
    jwksUrl,
    header.kid,
  );
  if (getJwksResult.isError) {
    return errorResult({
      errorMessage: 'Unexpected error when fetching JWKS',
      errorCategory: ErrorCategory.SERVER_ERROR,
    });
  }
  const jwks = getJwksResult.value;
  const localJwks = createLocalJWKSet({
    keys: jwks.keys,
  });

  let payload: JWTPayload;
  try {
    const verifiedJwt = await jwtVerify(jwt, localJwks, {
      algorithms: [expectedJwtData.algorithm],
      audience: expectedJwtData.audience,
      issuer: expectedJwtData.issuer,
    });
    payload = verifiedJwt.payload;
  } catch (error: unknown) {
    const errorMessage = getJwtVerifyErrorMessage(error);
    logger.error(LogMessage.JWT_VERIFICATION_FAILURE, {
      error,
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

  if (!payload.sub || !expectedJwtData.allowedAppId.includes(payload.sub)) {
    const errorMessage = 'JWT sub claim is not in the list of allowed App IDs';
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

  const jwtReplayCacheResult = dependencies.jwtReplayCache.consume(
    payload.jti,
    payload.exp,
  );
  if (jwtReplayCacheResult.isError) {
    const errorMessage = 'JWT replay detected';
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

function getJwtVerifyErrorMessage(error: unknown): string {
  let errorMessage = 'JWT signature verification failed';

  if (error instanceof errors.JWTClaimValidationFailed) {
    errorMessage = 'JWT claim(s) are invalid';
  }

  if (error instanceof errors.JWTExpired) {
    errorMessage = 'JWT expired';
  }

  if (error instanceof errors.JWSSignatureVerificationFailed) {
    errorMessage = 'JWT signature is invalid';
  }

  if (error instanceof errors.JOSEAlgNotAllowed) {
    errorMessage = 'JWT algorithm is not allowed';
  }

  if (
    error instanceof errors.JWTInvalid ||
    error instanceof errors.JWSInvalid
  ) {
    errorMessage = 'JWT is malformed';
  }

  return errorMessage;
}
