import type { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import { randomUUID } from 'node:crypto';
import { IssueReaderCertRequest, IssueReaderCertResponse, AttestationResult } from './types';
import { validateRequest, createErrorResponse } from './validation';
import { verifyAndroidAttestation } from './android-attestation';
import { verifyIOSAttestation } from './ios-attestation';
import { DynamoDBClient, DeleteItemCommand } from '@aws-sdk/client-dynamodb';

const logger = new Logger();
const dynamoClient = new DynamoDBClient({});

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
    const certificate = await issueCertificate();

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
  const tableName = process.env.NONCE_TABLE_NAME;
  if (!tableName) {
    logger.error('Dynamodb table not found');
    return false;
  }

  try {
    const deleteCommand = new DeleteItemCommand({
      TableName: tableName,
      Key: {
        nonceValue: { S: nonce },
      },
      ReturnValues: 'ALL_OLD',
      ConditionExpression: '#timeToLive > :now',
      ExpressionAttributeNames: {
        '#timeToLive': 'timeToLive',
      },
      ExpressionAttributeValues: {
        ':now': { N: Math.floor(Date.now() / 1000).toString() },
      },
    });

    const result = await dynamoClient.send(deleteCommand);
    const success = !!result.Attributes;
    logger.info('Nonce verification result', { nonce, success });
    return success;
  } catch (error) {
    logger.error('Error verifying nonce', { nonce, error: error instanceof Error ? error.message : error });
    return false;
  }
}

async function verifyAttestation(request: IssueReaderCertRequest): Promise<AttestationResult> {
  if (request.platform === 'ios') {
    return verifyIOSAttestation(request);
  } else {
    return verifyAndroidAttestation(request);
  }
}

async function issueCertificate(): Promise<IssueReaderCertResponse> {
  const readerId = `reader-${randomUUID()}`;
  const now = new Date();
  const notAfter = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours validity (ISO 18013-5 compliant)

  // Implement actual certificate issuance with ISO 18013-5 compliance:
  // - BasicConstraints: CA:FALSE (end-entity certificate)
  // - KeyUsage: digitalSignature, keyAgreement
  // - ExtendedKeyUsage: mDL reader authentication OID
  // - CertificatePolicies: ISO 18013-5 policy OIDs
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
