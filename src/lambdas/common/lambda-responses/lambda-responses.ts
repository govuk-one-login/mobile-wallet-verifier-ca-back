import { APIGatewayProxyResult } from 'aws-lambda';

export interface IssueReaderCertResponseBody {
  certChain: string;
}

export const okResponse = (
  awsRequestId: string,
  body: IssueReaderCertResponseBody,
): APIGatewayProxyResult => {
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      'X-Request-Id': awsRequestId,
    },
    body: JSON.stringify(body),
  };
};

export const unauthorizedResponse = (
  message: string,
): APIGatewayProxyResult => {
  return {
    headers: { 'Content-Type': 'application/json' },
    statusCode: 401,
    body: JSON.stringify({
      code: 'unauthorized',
      message,
    }),
  };
};

export const badRequestResponse = (message: string) => {
  return {
    headers: { 'Content-Type': 'application/json' },
    statusCode: 400,
    body: JSON.stringify({
      code: 'bad_request',
      message,
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
