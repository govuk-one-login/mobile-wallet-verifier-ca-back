import {
  getApiGatewayApiInstance,
  getMockServicesApiInstance,
} from './api-instance.ts';
import type { HttpResponseSnapshot } from './api-instance.ts';

const ISSUE_READER_CERT_PATH = '/issue-reader-cert';
const MOCK_ISSUE_CERT_REQUEST_PATH = '/mock-issue-cert-request';

export interface MockIssueReaderCertRequest {
  headers: {
    'X-Firebase-AppCheck': string;
  };
  body: {
    csrPem: string;
  };
}

export async function requestMockIssueReaderCertRequest(): Promise<MockIssueReaderCertRequest> {
  const responseSnapshot = await getMockServicesApiInstance().get(
    MOCK_ISSUE_CERT_REQUEST_PATH,
  );
  if (responseSnapshot.status !== 200) {
    throw new Error(
      `Mock issue cert request endpoint returned ${responseSnapshot.status} for ${responseSnapshot.url}: ${responseSnapshot.body}`,
    );
  }

  let parsedResponse: unknown;
  try {
    parsedResponse = JSON.parse(responseSnapshot.body);
  } catch {
    throw new Error(
      `Mock issue cert request endpoint did not return valid JSON for ${responseSnapshot.url}: ${responseSnapshot.body}`,
    );
  }

  if (!isMockIssueReaderCertRequest(parsedResponse)) {
    throw new Error(
      `Mock issue cert request endpoint returned an unexpected payload for ${responseSnapshot.url}: ${responseSnapshot.body}`,
    );
  }

  return parsedResponse;
}

export interface IssueReaderCertRequest {
  headers?: {
    'X-Firebase-AppCheck'?: string;
  };
  body: unknown;
}

export async function requestIssueReaderCert(
  request: IssueReaderCertRequest,
): Promise<HttpResponseSnapshot> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  const appCheckJwt = request.headers?.['X-Firebase-AppCheck'];
  if (appCheckJwt !== undefined) {
    headers['X-Firebase-AppCheck'] = appCheckJwt;
  }

  return getApiGatewayApiInstance().post(
    ISSUE_READER_CERT_PATH,
    JSON.stringify(request.body),
    headers,
  );
}

function isMockIssueReaderCertRequest(
  value: unknown,
): value is MockIssueReaderCertRequest {
  if (!isRecord(value)) {
    return false;
  }

  const headers = value.headers;
  if (!isRecord(headers)) {
    return false;
  }

  const body = value.body;
  if (!isRecord(body)) {
    return false;
  }

  const firebaseAppCheck = headers['X-Firebase-AppCheck'];
  const csrPem = body['csrPem'];

  return (
    typeof firebaseAppCheck === 'string' &&
    firebaseAppCheck.trim().length > 0 &&
    typeof csrPem === 'string' &&
    csrPem.trim().length > 0
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
