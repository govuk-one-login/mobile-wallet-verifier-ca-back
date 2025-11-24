import { PutItemCommand } from '@aws-sdk/client-dynamodb';
import type { APIGatewayProxyEvent, Context } from 'aws-lambda';

const mockSend = jest.fn();

jest.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: jest.fn(() => ({ send: mockSend })),
  PutItemCommand: jest.fn()
}));

jest.mock('crypto', () => ({
  randomUUID: jest.fn(() => 'test-uuid')
}));

import { handler } from '../../../src/lambdas/nonce-service/handler';

const mockEvent: APIGatewayProxyEvent = {
  httpMethod: 'POST',
  path: '/nonce',
  requestContext: {} as any
} as APIGatewayProxyEvent;

const mockContext: Context = {
  awsRequestId: 'test-request-id'
} as Context;

describe('Nonce Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.NONCE_TABLE_NAME = 'test-table';
  });

  it('should return 404 for invalid requests', async () => {
    const result = await handler({ ...mockEvent, httpMethod: 'GET' }, mockContext);
    expect(result.statusCode).toBe(404);
  });

  it('should return 500 when table name missing', async () => {
    delete process.env.NONCE_TABLE_NAME;
    const result = await handler(mockEvent, mockContext);
    expect(result.statusCode).toBe(500);
  });

  it('should create nonce successfully', async () => {
    mockSend.mockResolvedValueOnce({});
    const result = await handler(mockEvent, mockContext);
    
    expect(result.statusCode).toBe(201);
    expect(mockSend).toHaveBeenCalled();
    const body = JSON.parse(result.body);
    expect(body.nonce).toBe('test-uuid');
    expect(body.expiresAt).toBeDefined();
  });

  it('should handle DynamoDB errors', async () => {
    mockSend.mockRejectedValueOnce(new Error('DB error'));
    const result = await handler(mockEvent, mockContext);
    expect(result.statusCode).toBe(500);
  });

  it('should handle non-Error exceptions', async () => {
    mockSend.mockRejectedValueOnce('string error');
    const result = await handler(mockEvent, mockContext);
    expect(result.statusCode).toBe(500);
  });
});