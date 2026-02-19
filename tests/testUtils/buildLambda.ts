import { APIGatewayProxyEvent, Context } from 'aws-lambda';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function buildRequest(overrides?: any): APIGatewayProxyEvent {
  const defaultRequest = {
    httpMethod: 'get',
    body: '',
    headers: {
      'x-correlation-id': 'mockCorrelationId',
    },
    isBase64Encoded: false,
    multiValueHeaders: {},
    multiValueQueryStringParameters: {},
    path: '/mockPath',
    pathParameters: {},
    queryStringParameters: {},
    requestContext: {
      accountId: '123456789012',
      apiId: '1234',
      authorizer: {},
      httpMethod: 'get',
      identity: { sourceIp: '1.1.1.1' },
      path: '/mockPath',
      protocol: 'HTTP/1.1',
      requestId: 'c6af9ac6-7b61-11e6-9a41-93e8deadbeef',
      requestTimeEpoch: 1428582896000,
      resourceId: '123456',
      resourcePath: '/mockPath',
      stage: 'mockStage',
    },
    resource: '',
    stageVariables: {},
  };
  return { ...defaultRequest, ...overrides };
}
export function buildLambdaContext(): Context {
  return {
    callbackWaitsForEmptyEventLoop: true,
    functionName: 'lambdaFunctionName',
    functionVersion: '1',
    invokedFunctionArn: 'arn:12345',
    memoryLimitInMB: '1028',
    awsRequestId: 'awsRequestId',
    logGroupName: 'logGroup',
    logStreamName: 'logStream',
    getRemainingTimeInMillis: () => {
      return 2000;
    },
    done: function (): void {},
    fail: function (): void {},
    succeed: function (): void {},
  };
}
