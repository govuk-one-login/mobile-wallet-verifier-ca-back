import { errors } from 'jose';

export function getVerifyJwtErrorMessage(error: unknown): string {
  let errorMessage = 'App Check JWT verification failed';

  if (error instanceof errors.JWTClaimValidationFailed) {
    const invalidClaim = error.claim;
    if (invalidClaim) {
      errorMessage = `App Check JWT ${invalidClaim} claim is invalid`;
    } else {
      errorMessage = 'App Check JWT claim(s) are invalid';
    }
  }

  if (error instanceof errors.JWTExpired) {
    errorMessage = 'App Check JWT expired';
  }

  if (error instanceof errors.JWSSignatureVerificationFailed) {
    errorMessage = 'App Check JWT signature is invalid';
  }

  if (error instanceof errors.JOSEAlgNotAllowed) {
    errorMessage = 'App Check JWT algorithm is not allowed';
  }

  if (
    error instanceof errors.JWTInvalid ||
    error instanceof errors.JWSInvalid
  ) {
    errorMessage = 'App Check JWT is malformed';
  }

  return errorMessage;
}
