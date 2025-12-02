import type { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import { randomUUID } from 'node:crypto';
import { IssueReaderCertRequest, IssueReaderCertResponse, AttestationResult } from './types.ts';
import { validateRequest, createErrorResponse } from './validation.ts';
import { verifyAndroidAttestation } from './android-attestation.ts';
import { verifyIOSAttestation } from './ios-attestation.ts';

const logger = new Logger();

export const handler = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  logger.info('Reader certificate service handler invoked', { httpMethod: event.httpMethod, path: event.path });

  if (event.httpMethod !== 'POST' || event.path !== '/issue-reader-cert') {
    logger.warn('Invalid request method or path', { httpMethod: event.httpMethod, path: event.path });
    return createErrorResponse(404, 'not_found', 'Endpoint not found');
  }

  try {
    const request: IssueReaderCertRequest = JSON.parse(event.body || '{}');
    
    // Validate request
    const validationError = validateRequest(request);
    if (validationError) {
      return validationError;
    }

    // Verify nonce
    const nonceValid = await verifyNonce(request.nonce);
    if (!nonceValid) {
      return createErrorResponse(409, 'nonce_replayed', 'Nonce has already been consumed');
    }

    // Verify platform attestation
    const attestationResult = await verifyAttestation(request);
    if (!attestationResult.valid) {
      return createErrorResponse(403, attestationResult.code || 'attestation_failed', attestationResult.message || 'Platform attestation failed');
    }

    // Issue certificate
    const certificate = await issueCertificate(request);
    
    logger.info('Certificate issued successfully', { readerId: certificate.readerId });
    
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-Id': context.awsRequestId,
      },
      body: JSON.stringify(certificate),
    };

  } catch (error) {
    logger.error('Error processing certificate request', { error: error instanceof Error ? error.message : error });
    return createErrorResponse(500, 'internal_error', 'Internal server error issuing certificate');
  }
};

async function verifyNonce(nonce: string): Promise<boolean> {
  // TODO: Implement nonce verification against DynamoDB
  logger.info('Verifying nonce', { nonce });
  return true;
}

async function verifyAttestation(request: IssueReaderCertRequest): Promise<AttestationResult> {
  if (request.platform === 'ios') {
    return verifyIOSAttestation(request);
  } else {
    return verifyAndroidAttestation(request);
  }
}

async function issueCertificate(request: IssueReaderCertRequest): Promise<IssueReaderCertResponse> {
  const readerId = `reader-${randomUUID()}`;
  const now = new Date();
  const notAfter = new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes validity

  // TODO: Implement actual certificate issuance
  const mockCertificate: IssueReaderCertResponse = {
    readerId,
    certChain: {
      leaf: `-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----`,
      intermediate: `-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----`,
    },
    profile: 'Reader',
    notBefore: now.toISOString(),
    notAfter: notAfter.toISOString(),
  };

  return mockCertificate;
}