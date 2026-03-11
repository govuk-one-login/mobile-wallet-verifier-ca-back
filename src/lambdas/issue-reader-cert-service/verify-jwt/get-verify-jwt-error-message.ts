import { errors } from 'jose';

export function getVerifyJwtErrorMessage(error: unknown): string {
  let errorMessage = 'JWT verification failed';

  if (error instanceof errors.JWTClaimValidationFailed) {
    const invalidClaim = error.claim;
    if (invalidClaim) {
      errorMessage = `JWT ${invalidClaim} claim is invalid`;
    } else {
      errorMessage = 'JWT claim(s) are invalid';
    }
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
