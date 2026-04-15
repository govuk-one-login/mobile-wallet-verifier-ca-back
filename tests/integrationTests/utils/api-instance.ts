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

function getApiGatewayApiInstance(): ApiInstance {
  return getInstance(getRequiredEnvVar('API_GATEWAY_URL'));
}

function getMockServicesApiInstance(): ApiInstance {
  return getInstance(getRequiredEnvVar('MOCK_SERVICES_API_URL'));
}

export {
  getApiGatewayApiInstance,
  getMockServicesApiInstance,
  buildUrl,
  API_GATEWAY_URL,
  MOCK_SERVICES_API_URL,
  getRequiredEnvVar
};

function buildUrl(baseUrl: string, path: string): string {
  const normalizedBaseUrl = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  const normalizedPath = path.startsWith('/') ? path.slice(1) : path;

  return new URL(normalizedPath, normalizedBaseUrl).toString();
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

function getRequiredEnvVar(envVarName: 'API_GATEWAY_URL' | 'MOCK_SERVICES_API_URL'): string {
  const envVar = process.env[envVarName]?.trim();

  if (!envVar) {
    throw new Error(`${envVarName} must be set before running integration tests`);
  }

  return envVar;
}
