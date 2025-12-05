import type { APIGatewayProxyResult } from 'aws-lambda';
import { Pkcs10CertificateRequest, X509Certificate } from '@peculiar/x509';
import { IssueReaderCertRequest, ErrorResponse } from './types.ts';
import { ANDROID_ATTESTATION_CONFIG } from '../../../common/const.ts';

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

  // Validate CSR
  let csr: Pkcs10CertificateRequest;
  try {
    if (!request.csrPem?.includes('BEGIN CERTIFICATE REQUEST')) throw new Error();
    csr = new Pkcs10CertificateRequest(request.csrPem);
  } catch (error) {
    return createErrorResponse(400, 'bad_request', 'CSR is not a valid PKCS#10 structure', { field: 'csrPem' });
  }

  // Validate CSR content for ISO 18013-5 compliance
  const csrValidation = validateCSRContent(csr);
  if (csrValidation) {
    return csrValidation;
  }

  // Validate CSR subject DN for ISO 18013-5 compliance
  const dnValidation = validateReaderCertSubject(csr.subject);
  if (dnValidation) {
    return dnValidation;
  }

  if (request.platform === 'ios' && !request.appAttest) {
    return createErrorResponse(400, 'bad_request', 'Missing appAttest for iOS platform');
  }

  if (request.platform === 'android' && (!request.keyAttestationChain || !request.playIntegrityToken)) {
    return createErrorResponse(400, 'bad_request', 'Missing keyAttestationChain or playIntegrityToken for Android platform');
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
export function createErrorResponse(statusCode: number, code: string, message: string, details?: Record<string, unknown>): APIGatewayProxyResult {
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
 */
function validateReaderCertSubject(subject: string): APIGatewayProxyResult | null {
  const dn = Object.fromEntries(
    subject.split(',').map(part => {
      const [key, ...value] = part.trim().split('=');
      return [key?.trim(), value.join('=')?.trim()];
    }).filter(([key, value]) => key && value)
  );
  
  const required = [['CN', 'Common Name'], ['O', 'Organization'], ['C', 'Country']];
  for (const [field, name] of required) {
    if (!dn[field]) {
      return createErrorResponse(400, 'invalid_subject_dn', `CSR subject missing required ${name} (${field})`);
    }
  }
  
  if (!isValidCountryCode(dn.C)) {
    return createErrorResponse(400, 'invalid_subject_dn', 'Country (C) must be valid ISO 3166-1 code');
  }
  
  return null;
}

/**
 * Validates CSR content against ISO 18013-5 requirements
 */
function validateCSRContent(csr: Pkcs10CertificateRequest): APIGatewayProxyResult | null {
  // Validate public key algorithm (ISO 18013-5 requires ECDSA)
  const keyAlgorithm = csr.publicKey.algorithm.name;
  if (keyAlgorithm !== ANDROID_ATTESTATION_CONFIG.VALID_KEY_ALGORITHM) {
    return createErrorResponse(400, 'invalid_key_algorithm', `CSR must use ECDSA algorithm, got ${keyAlgorithm}`);
  }

  // Validate ECDSA curve (ISO 18013-5 approved curves)
  const namedCurve = (csr.publicKey.algorithm as any).namedCurve;
  if (!ANDROID_ATTESTATION_CONFIG.VALID_ECDSA_CURVES.includes(namedCurve)) {
    return createErrorResponse(400, 'invalid_key_curve', `CSR must use approved ECDSA curve (${ANDROID_ATTESTATION_CONFIG.VALID_ECDSA_CURVES.join(', ')}), got ${namedCurve}`);
  }

  return null;
}

/**
 * Validates ISO 3166-1 alpha-2 country code using built-in Intl API
 */
function isValidCountryCode(code: string): boolean {
  try {
    const displayName = new Intl.DisplayNames(['en'], { type: 'region' }).of(code);
    return displayName !== code && displayName !== undefined;
  } catch {
    return false;
  }
}

