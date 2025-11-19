import { PutItemCommand } from '@aws-sdk/client-dynamodb';
import type { APIGatewayProxyEvent, Context } from 'aws-lambda';

const mockSend = jest.fn();

jest.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: jest.fn(() => ({
    send: mockSend
  })),
  PutItemCommand: jest.fn()
}));

jest.mock('crypto', () => ({
  randomUUID: jest.fn(() => 'test-uuid-1234-5678-9abc-def012345678')
}));

// Import handler after mocks are set up
import { handler } from '../../../src/lambdas/nonce-service/handler';

const mockEvent: APIGatewayProxyEvent = {
  httpMethod: 'POST',
  path: '/nonce',
  body: null,
  headers: {},
  multiValueHeaders: {},
  isBase64Encoded: false,
  pathParameters: null,
  queryStringParameters: null,
  multiValueQueryStringParameters: null,
  stageVariables: null,
  requestContext: {} as any,
  resource: ''
};

const mockContext: Context = {
  awsRequestId: 'test-request-id',
  functionName: 'test-function',
  functionVersion: '1',
  invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test',
  memoryLimitInMB: '128',
  getRemainingTimeInMillis: () => 30000,
  callbackWaitsForEmptyEventLoop: true,
  logGroupName: 'test-log-group',
  logStreamName: 'test-log-stream',
  identity: undefined,
  clientContext: undefined,
  done: jest.fn(),
  fail: jest.fn(),
  succeed: jest.fn()
};

describe('Nonce Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.NONCE_TABLE_NAME = 'test-nonce-table';
  });

  it('should return 404 for non-POST requests', async () => {
    const event = { ...mockEvent, httpMethod: 'GET' };
    const result = await handler(event, mockContext);
    
    expect(result.statusCode).toBe(404);
    const body = JSON.parse(result.body);
    expect(body.status).toBe(404);
    expect(body.detail).toBe('Not Found');
  });

  it('should return 404 for wrong path', async () => {
    const event = { ...mockEvent, path: '/wrong' };
    const result = await handler(event, mockContext);
    
    expect(result.statusCode).toBe(404);
    const body = JSON.parse(result.body);
    expect(body.status).toBe(404);
    expect(body.detail).toBe('Not Found');
  });

  it('should return 500 when NONCE_TABLE_NAME is not set', async () => {
    delete process.env.NONCE_TABLE_NAME;
    const result = await handler(mockEvent, mockContext);
    
    expect(result.statusCode).toBe(500);
    expect(result.headers!['Content-Type']).toBe('application/problem+json');
  });

  it('should create nonce successfully', async () => {
    mockSend.mockResolvedValueOnce({});
    
    const result = await handler(mockEvent, mockContext);
    
    expect(result.statusCode).toBe(201);
    expect(mockSend).toHaveBeenCalledWith(expect.any(PutItemCommand));
    
    const body = JSON.parse(result.body);
    expect(body.nonce).toBe('test-uuid-1234-5678-9abc-def012345678');
    expect(body.expiresAt).toBeDefined();
  });

  it('should return 500 on DynamoDB error', async () => {
    mockSend.mockRejectedValueOnce(new Error('DynamoDB error'));
    
    const result = await handler(mockEvent, mockContext);
    
    console.log('Mock calls:', mockSend.mock.calls.length);
    console.log('Result status:', result.statusCode);
    console.log('Result body:', result.body);
    
    expect(result.statusCode).toBe(500);
    expect(result.headers!['Content-Type']).toBe('application/problem+json');
  });
});