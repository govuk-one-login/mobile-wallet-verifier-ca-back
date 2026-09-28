import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { Sha256 } from '@aws-crypto/sha256-js';
import { HttpRequest } from '@smithy/protocol-http';
import { SignatureV4 } from '@smithy/signature-v4';

export interface HttpResponseSnapshot {
  status: number;
  body: string;
  headers: Record<string, string>;
  url: string;
}

export interface ApiInstance {
  get: (
    path: string,
    headers?: Record<string, string>,
  ) => Promise<HttpResponseSnapshot>;
  post: (
    path: string,
    body: string,
    headers?: Record<string, string>,
  ) => Promise<HttpResponseSnapshot>;
}

const AWS_REGION = process.env.AWS_REGION ?? 'eu-west-2';
const EXECUTE_API_SERVICE = 'execute-api';

// The CA backend API must be reached at its REGIONAL execute-api host for SigV4:
// signing covers the Host header, and the CloudFront custom domain rewrites Host
// to the origin before the request reaches API Gateway, which invalidates the
// signature. CA_BACKEND_API_URL must therefore be the regional API base URL
// (the ApiGatewayDomainName / IssueReaderCertRegionalEndpoint stack output),
// never the CloudFront custom domain. run-tests.sh sets it from the pipeline's
// CFN_ApiGatewayDomainName output; set it manually for local runs.
const API_GATEWAY_URL = requireEnv('CA_BACKEND_API_URL');

// Mock services live on a separate API that is NOT SigV4-protected.
const MOCK_SERVICES_API_URL = requireEnv('MOCK_SERVICES_API_URL');

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') {
    throw new Error(
      `Environment variable ${name} must be set to the deployed stack's API base URL. ` +
        `For SigV4 this must be the regional execute-api host, not the CloudFront custom domain.`,
    );
  }
  return value;
}

async function signedFetch(
  method: 'GET' | 'POST',
  url: string,
  headers: Record<string, string>,
  body?: string,
): Promise<Response> {
  const parsed = new URL(url);

  const signer = new SignatureV4({
    service: EXECUTE_API_SERVICE,
    region: AWS_REGION,
    credentials: defaultProvider(),
    sha256: Sha256,
  });

  // Host must be present for SigV4 and must match the host the request is sent
  // to (the regional execute-api host).
  const requestToSign = new HttpRequest({
    method,
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    path: parsed.pathname,
    query: Object.fromEntries(parsed.searchParams.entries()),
    headers: {
      ...headers,
      host: parsed.host,
    },
    body,
  });

  const signed = await signer.sign(requestToSign);

  return fetch(url, {
    method,
    headers: signed.headers as Record<string, string>,
    body,
  });
}

function getInstance(baseUrl: string, sign: boolean): ApiInstance {
  return {
    async get(
      path: string,
      headers: Record<string, string> = {},
    ): Promise<HttpResponseSnapshot> {
      const url = buildUrl(baseUrl, path);
      const response = sign
        ? await signedFetch('GET', url, headers)
        : await fetch(url, { method: 'GET', headers });

      return captureResponse(response);
    },

    async post(
      path: string,
      body: string,
      headers: Record<string, string> = {},
    ): Promise<HttpResponseSnapshot> {
      const url = buildUrl(baseUrl, path);
      const response = sign
        ? await signedFetch('POST', url, headers, body)
        : await fetch(url, { method: 'POST', headers, body });

      return captureResponse(response);
    },
  };
}

// SigV4-signed instance for the protected CA backend API.
export function getApiGatewayApiInstance(): ApiInstance {
  return getInstance(API_GATEWAY_URL, true);
}

// Unsigned instance for the protected CA backend API, used to assert that
// unauthenticated requests are rejected with 403.
export function getUnsignedApiGatewayApiInstance(): ApiInstance {
  return getInstance(API_GATEWAY_URL, false);
}

// Mock services are not SigV4-protected, so requests are sent unsigned.
export function getMockServicesApiInstance(): ApiInstance {
  return getInstance(MOCK_SERVICES_API_URL, false);
}

function buildUrl(baseUrl: string, path: string): string {
  const normalisedBaseUrl = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  const normalisedPath = path.startsWith('/') ? path.slice(1) : path;

  return new URL(normalisedPath, normalisedBaseUrl).toString();
}

async function captureResponse(
  response: Response,
): Promise<HttpResponseSnapshot> {
  return {
    status: response.status,
    body: await response.text(),
    headers: Object.fromEntries(response.headers.entries()),
    url: response.url,
  };
}
