import type { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import { randomUUID } from 'node:crypto';

const logger = new Logger();

interface IssueReaderCertRequest {
  platform: 'ios' | 'android';
  nonce: string;
  csrPem: string;
  appAttest?: {
    keyId: string;
    attestationObject: string;
    clientDataJSON: string;
  };
  keyAttestationChain?: string[];
  playIntegrityToken?: string;
}

interface IssueReaderCertResponse {
  readerId: string;
  certChain: {
    leaf: string;
    intermediate?: string;
  };
  profile: string;
  notBefore: string;
  notAfter: string;
}

interface ErrorResponse {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

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
      return createErrorResponse(
        403,
        attestationResult.code || 'attestation_failed',
        attestationResult.message || 'Platform attestation failed',
      );
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

function validateRequest(request: IssueReaderCertRequest): APIGatewayProxyResult | null {
  if (!request.platform || !['ios', 'android'].includes(request.platform)) {
    return createErrorResponse(400, 'bad_request', 'Invalid or missing platform');
  }

  if (!request.nonce) {
    return createErrorResponse(400, 'bad_request', 'Missing nonce');
  }

  if (!request.csrPem || !request.csrPem.includes('BEGIN CERTIFICATE REQUEST')) {
    return createErrorResponse(400, 'bad_request', 'CSR is not a valid PKCS#10 structure', { field: 'csrPem' });
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

  return null;
}

async function verifyNonce(nonce: string): Promise<boolean> {
  // TODO: Implement nonce verification against DynamoDB
  // For now, return true as placeholder
  logger.info('Verifying nonce', { nonce });
  return true;
}

async function verifyAttestation(
  request: IssueReaderCertRequest,
): Promise<{ valid: boolean; code?: string; message?: string }> {
  if (request.platform === 'ios') {
    return verifyIOSAttestation(request);
  } else {
    return verifyAndroidAttestation(request);
  }
}

async function verifyIOSAttestation(
  request: IssueReaderCertRequest,
): Promise<{ valid: boolean; code?: string; message?: string }> {
  // TODO: Implement iOS App Attest verification
  logger.info('Verifying iOS App Attest', { keyId: request.appAttest?.keyId });
  return { valid: true };
}

async function verifyAndroidAttestation(
  request: IssueReaderCertRequest,
): Promise<{ valid: boolean; code?: string; message?: string }> {
  // TODO: Implement Android Play Integrity + Key Attestation verification
  logger.info('Verifying Android attestation', { chainLength: request.keyAttestationChain?.length });
  return { valid: true };
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

  // Logger to be removed in the implementation
  logger.info('printing request to bypass linting error', { request });

  return mockCertificate;
}

function createErrorResponse(
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
