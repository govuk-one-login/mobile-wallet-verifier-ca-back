import { APIGatewayProxyResult } from 'aws-lambda';

export const okResponse = (awsRequestId: string): APIGatewayProxyResult => {
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      'X-Request-Id': awsRequestId,
    },
    body: 'OK',
  };
};

export const unauthorizedResponse = (
  errorDescription: string,
): APIGatewayProxyResult => {
  return {
    headers: { 'Content-Type': 'application/json' },
    statusCode: 401,
    body: JSON.stringify({
      code: 'unauthorized',
      message: errorDescription,
    }),
  };
};

export const serverErrorResponse: APIGatewayProxyResult = {
  headers: { 'Content-Type': 'application/json' },
  statusCode: 500,
  body: JSON.stringify({
    code: 'server_error',
    message: 'Server Error',
  }),
};
