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

const API_GATEWAY_URL = 'https://api.verifier-ca.build.account.gov.uk';
const MOCK_SERVICES_API_URL = 'https://mock.verifier-ca.build.account.gov.uk';

function getInstance(baseUrl: string): ApiInstance {
  return {
    async get(
      path: string,
      headers?: Record<string, string>,
    ): Promise<HttpResponseSnapshot> {
      const response = await fetch(buildUrl(baseUrl, path), {
        method: 'GET',
        headers,
      });

      return captureResponse(response);
    },

    async post(
      path: string,
      body: string,
      headers?: Record<string, string>,
    ): Promise<HttpResponseSnapshot> {
      const response = await fetch(buildUrl(baseUrl, path), {
        method: 'POST',
        headers,
        body,
      });

      return captureResponse(response);
    },
  };
}

export function getApiGatewayApiInstance(): ApiInstance {
  return getInstance(API_GATEWAY_URL);
}

export function getMockServicesApiInstance(): ApiInstance {
  return getInstance(MOCK_SERVICES_API_URL);
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
