import type { APIGatewayProxyResult } from 'aws-lambda';
import { Pkcs10CertificateRequest, X509Certificate } from '@peculiar/x509';
import { IssueReaderCertRequest, ErrorResponse } from './types.js';

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
  try {
    if (!request.csrPem?.includes('BEGIN CERTIFICATE REQUEST')) throw new Error();
    new Pkcs10CertificateRequest(request.csrPem);
  } catch (error) {
    return createErrorResponse(400, 'bad_request', 'Invalid CSR', { field: 'csrPem' });
  }

  if (request.platform === 'ios' && !request.appAttest) {
    return createErrorResponse(400, 'bad_request', 'Missing appAttest for iOS platform');
  }

  if (request.platform === 'android' && (!request.keyAttestationChain || !request.playIntegrityToken)) {
    return createErrorResponse(400, 'bad_request', 'Missing keyAttestationChain or playIntegrityToken for Android platform');
  }
  
  // Validate certificate chain format for Android
  if (request.platform === 'android' && request.keyAttestationChain) {
    for (let i = 0; i < request.keyAttestationChain.length; i++) {
      try {
        const derBuffer = Buffer.from(request.keyAttestationChain[i], 'base64');
        new X509Certificate(derBuffer);
      } catch (error) {
        return createErrorResponse(400, 'bad_request', `Certificate ${i} is not valid X.509 ASN.1 format`, { field: 'keyAttestationChain' });
      }
    }
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