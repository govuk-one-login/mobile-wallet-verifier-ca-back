import type { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import { randomUUID } from 'node:crypto';
import { IssueReaderCertResponse } from './types';
import { createErrorResponse } from './validation';

const logger = new Logger();

export const handler = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  logger.info('Reader certificate service handler invoked', { httpMethod: event.httpMethod, path: event.path });

  if (event.httpMethod !== 'POST' || event.path !== '/issue-reader-cert') {
    logger.warn('Invalid request method or path', { httpMethod: event.httpMethod, path: event.path });
    return createErrorResponse(404, 'not_found', 'Endpoint not found');
  }

  try {
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
