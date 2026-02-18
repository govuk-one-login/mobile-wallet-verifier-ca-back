import { Context, APIGatewayProxyEvent } from 'aws-lambda';
import { describe, it, beforeEach, expect, MockInstance, vi } from 'vitest';
import { handler } from './issue-reader-cert-handler';
import { logger } from '../common/logger/logger';
import '../../../tests/testUtils/matchers';

let consoleInfoSpy: MockInstance;

describe('Handler', () => {
  let event: APIGatewayProxyEvent;
  let context: Context;

  beforeEach(() => {
    consoleInfoSpy = vi.spyOn(console, 'info');
    context = buildLambdaContext();
    event = buildRequest();
  });

  describe('On every invocation', () => {
    beforeEach(async () => {
      logger.appendKeys({ testKey: 'testValue' });
      await handler(event, context);
    });

    it('Adds context, version and to log attributes and logs STARTED message', () => {
      expect(consoleInfoSpy).toHaveBeenCalledWithLogFields({
        messageCode: 'MOBILE_CA_ISSUE_READER_CERT_STARTED',
        functionVersion: '1',
        function_arn: 'arn:12345', // example field to verify that context has been added
      });
    });

    it('Clears pre-existing log attributes', async () => {
      expect(consoleInfoSpy).not.toHaveBeenCalledWithLogFields({
        testKey: 'testValue',
      });
    });
  });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildRequest(overrides?: any): APIGatewayProxyEvent {
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
function buildLambdaContext(): Context {
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
