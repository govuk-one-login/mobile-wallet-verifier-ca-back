import type { Context } from 'aws-lambda';

export interface NonceResponse {
  nonce: string;
  expiresAt: string;
}

export const createSuccessHeaders = (context: Context, nonceValue: string) => ({
  'Content-Type': 'application/json',
  'Location': `/nonce/${nonceValue}`,
  'Cache-Control': 'no-store',
  'Date': new Date().toUTCString(),
  'X-Request-Id': context.awsRequestId,
  'Access-Control-Allow-Origin': '*'
});

export const createErrorHeaders = () => ({
  'Content-Type': 'application/problem+json'
});

export const createProblemResponse = (status: number, detail: string, instance?: string) => ({
  type: 'https://api.example.com/problems/internal-error',
  title: 'Internal Server Error',
  status,
  detail,
  ...(instance && { instance })
});

export const createErrorResponse = (status: number, detail: string, instance?: string) => ({
  statusCode: status,
  headers: createErrorHeaders(),
  body: JSON.stringify(createProblemResponse(status, detail, instance))
});

export const createSuccessResponse = (context: Context, nonceValue: string, expiresAt: string) => {
  const responseBody: NonceResponse = { nonce: nonceValue, expiresAt };
  return {
    statusCode: 201,
    headers: createSuccessHeaders(context, nonceValue),
    body: JSON.stringify(responseBody)
  };
};