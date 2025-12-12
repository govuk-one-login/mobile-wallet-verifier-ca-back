import type { APIGatewayProxyResult } from 'aws-lambda';
import { Pkcs10CertificateRequest, PublicKey } from '@peculiar/x509';
import { Logger } from '@aws-lambda-powertools/logger';
import { IssueReaderCertRequest, ErrorResponse, AttestationResult } from './types';
import { ANDROID_ATTESTATION_CONFIG } from '../../../common/const';

const logger = new Logger();

/**
 * Validates the certificate issuance request
 * @param request - The certificate request to validate
 * @returns Error response if validation fails, null if valid
 */
export function validateRequest(request: IssueReaderCertRequest): APIGatewayProxyResult | null {
  if (!request.platform || !['ios', 'android'].includes(request.platform)) {
    return createErrorResponse(400, 'bad_request', 'Invalid or missing platform');
  }

  if (!request.nonce) {
    return createErrorResponse(400, 'bad_request', 'Missing nonce');
  }

  if (request.platform === 'ios' && !request.appAttest) {
    return createErrorResponse(400, 'bad_request', 'Missing appAttest for iOS platform');
  }

  if (request.platform === 'android' && (!request.keyAttestationChain || !request.playIntegrityToken)) {
    return createErrorResponse(
      400,
      'bad_request',
      'Missing keyAttestationChain or playIntegrityToken for Android platform',
    );
  }

  // Validate CSR format
  try {
    if (!request.csrPem?.includes('BEGIN CERTIFICATE REQUEST')) throw new Error('Invalid CSR format');
    new Pkcs10CertificateRequest(request.csrPem);
  } catch {
    return createErrorResponse(400, 'bad_request', 'CSR is not a valid PKCS#10 structure', { field: 'csrPem' });
  }

  return null;
}

/**
 * Creates a standardized error response
 * @param statusCode - HTTP status code
 * @param code - Error code
 * @param message - Error message
 * @param details - Optional additional error details
 * @returns API Gateway response object
 */
export function createErrorResponse(
  statusCode: number,
  code: string,
  message: string,
  details?: Record<string, unknown>,
): APIGatewayProxyResult {
  const errorResponse: ErrorResponse = {
    code,
    message,
    ...(details && { details }),
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(errorResponse),
  };
}

/**
 * Validates CSR subject DN against ISO 18013-5 reader certificate requirements
 * @param subject - The subject DN string from the CSR
 * @returns Attestation verification result
 */
export function validateReaderCertSubject(subject: string): AttestationResult {
  const dn = Object.fromEntries(
    subject
      .split(',')
      .map((part) => {
        const [key, ...value] = part.trim().split('=');
        return [key?.trim(), value.join('=')?.trim()];
      })
      .filter(([key, value]) => key && value),
  );

  const required = [
    ['CN', 'Common Name'],
    ['O', 'Organization'],
    ['C', 'Country'],
  ];
  for (const [field, name] of required) {
    if (!dn[field]) {
      return { valid: false, code: 'invalid_subject_dn', message: `CSR subject missing required ${name} (${field})` };
    }
  }

  // Validate ISO 3166-1 alpha-2 country code
  try {
    const displayName = new Intl.DisplayNames(['en'], { type: 'region' }).of(dn.C);
    if (displayName === dn.C || displayName === undefined) {
      return { valid: false, code: 'invalid_subject_dn', message: 'Country (C) must be valid ISO 3166-1 code' };
    }
  } catch {
    return { valid: false, code: 'invalid_subject_dn', message: 'Country (C) must be valid ISO 3166-1 code' };
  }

  return { valid: true };
}

/**
 * Validates CSR content and verifies it matches the attested device public key
 * This is a comprehensive validation that combines:
 * 1. CSR subject DN validation (ISO 18013-5 reader certificate requirements)
 * 2. CSR public key algorithm and curve validation (ISO 18013-5)
 * 3. Public key matching between CSR and attestation (prevents key substitution)
 *
 * @param csrPem - The certificate signing request in PEM format
 * @param attestedPublicKey - The public key from the attestation (PublicKey from @peculiar/x509)
 * @returns Attestation verification result
 */
export async function validateCSRContent(csrPem: string, attestedPublicKey: PublicKey): Promise<AttestationResult> {
  try {
    const csr = new Pkcs10CertificateRequest(csrPem);

    // Step 1: Validate CSR subject DN for ISO 18013-5 compliance
    const dnValidation = validateReaderCertSubject(csr.subject);
    if (!dnValidation.valid) {
      return dnValidation;
    }

    // Step 2: Validate CSR public key algorithm and curve (ISO 18013-5)
    const keyAlgorithm = csr.publicKey.algorithm.name;
    if (keyAlgorithm !== ANDROID_ATTESTATION_CONFIG.VALID_KEY_ALGORITHM) {
      return {
        valid: false,
        code: 'invalid_key_algorithm',
        message: `CSR must use ECDSA algorithm, got ${keyAlgorithm}`,
      };
    }

    const namedCurve = (csr.publicKey.algorithm as { namedCurve?: string }).namedCurve;
    if (!namedCurve || !ANDROID_ATTESTATION_CONFIG.VALID_ECDSA_CURVES.includes(namedCurve)) {
      return {
        valid: false,
        code: 'invalid_key_curve',
        message: `CSR must use approved ECDSA curve (${ANDROID_ATTESTATION_CONFIG.VALID_ECDSA_CURVES.join(', ')}), got ${namedCurve}`,
      };
    }

    // Step 3: Compare CSR public key with attested public key
    const csrSpkiThumbprint = await csr.publicKey.getThumbprint();
    const attestedSpkiThumbprint = await attestedPublicKey.getThumbprint();

    const keysMatch = Buffer.compare(Buffer.from(csrSpkiThumbprint), Buffer.from(attestedSpkiThumbprint)) === 0;

    if (!keysMatch) {
      return {
        valid: false,
        code: 'public_key_mismatch',
        message: 'CSR public key does not match attested device public key - potential key substitution attack',
      };
    }

    logger.info('CSR validation successful - valid algorithm, curve, and matches attested device key');
    return { valid: true };
  } catch (error) {
    logger.error('Error validating CSR content', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'invalid_csr', message: 'Failed to validate CSR content' };
  }
}
