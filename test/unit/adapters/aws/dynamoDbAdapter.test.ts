import { mockClient } from 'aws-sdk-client-mock';
import { DeleteCommand, DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import 'aws-sdk-client-mock-jest';
import { UUID } from 'node:crypto';
import { deleteNonce, getNonce, saveNonce } from '../../../../src/adapters/aws/dynamoDbAdapter';

const mockDynamoDb = mockClient(DynamoDBDocumentClient);

describe('DynamoDBAdapter', () => {
  beforeAll(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2025-11-24T00:00:00Z'));
  });

  afterAll(() => {
    jest.useRealTimers();
  });
  beforeEach(() => {
    mockDynamoDb.reset();
  });

  const tableName = 'testTable';
  const item = {
    nonceValue: '2e0fac05-4b38-480f-9cbd-b046eabe1e46' as UUID,
    timeToLive: getTimeToLiveEpoch(5),
    expiresAt: '2025-11-24T00:05:00Z',
  };

  it('should save a nonceValue to the database table', async () => {
    const putItemCommand = {
      TableName: tableName,
      Item: item,
    };

    mockDynamoDb.on(PutCommand).resolves({});

    await expect(saveNonce(tableName, item)).resolves.not.toThrow();
    expect(mockDynamoDb).toHaveReceivedCommandWith(PutCommand, putItemCommand);
  });

  it('should throw the error thrown by dynamoDb client when trying to save a nonce value', async () => {
    const putItemCommand = {
      TableName: tableName,
      Item: item,
    };
    mockDynamoDb.on(PutCommand).rejectsOnce('DATABASE_ERROR');

    await expect(saveNonce(tableName, item)).rejects.toThrow('DATABASE_ERROR');
    expect(mockDynamoDb).toHaveReceivedCommandWith(PutCommand, putItemCommand);
  });

  it('should get a nonce value from the database table by ID', async () => {
    const getItemCommand = {
      TableName: tableName,
      Key: {
        nonceValue: '2e0fac05-4b38-480f-9cbd-b046eabe1e46',
      },
    };
    mockDynamoDb.on(GetCommand).resolvesOnce({ Item: item });
    const response = await getNonce(tableName, '2e0fac05-4b38-480f-9cbd-b046eabe1e46');

    expect(response).toEqual(item);
    expect(mockDynamoDb).toHaveReceivedCommandWith(GetCommand, getItemCommand);
  });

  it('should return undefined if the nonce value does not exist', async () => {
    mockDynamoDb.on(GetCommand).resolvesOnce({});

    const response = await getNonce(tableName, '2e0fac05-4b38-480f-9cbd-b046eabe1e46');

    expect(response).toEqual(undefined);
  });

  it('should throw the error thrown by dynamoDb client when trying to get a nonce value', async () => {
    mockDynamoDb.on(GetCommand).rejectsOnce('SOME_ERROR');

    await expect(getNonce(tableName, '2e0fac05-4b38-480f-9cbd-b046eabe1e46')).rejects.toThrow('SOME_ERROR');
  });

  it('should delete a nonce value from the database table by ID', async () => {
    const deleteItemCommand = {
      TableName: tableName,
      Key: {
        nonceValue: '2e0fac05-4b38-480f-9cbd-b046eabe1e46',
      },
    };
    mockDynamoDb.on(GetCommand).resolvesOnce({ Item: item });
    await deleteNonce(tableName, '2e0fac05-4b38-480f-9cbd-b046eabe1e46');

    await expect(deleteNonce(tableName, '2e0fac05-4b38-480f-9cbd-b046eabe1e46')).resolves.not.toThrow();
    expect(mockDynamoDb).toHaveReceivedCommandWith(DeleteCommand, deleteItemCommand);
  });

  it('should throw the error thrown by dynamoDb client when trying to delete a nonce value', async () => {
    mockDynamoDb.on(DeleteCommand).rejectsOnce('SOME_ERROR');

    await expect(deleteNonce(tableName, '2e0fac05-4b38-480f-9cbd-b046eabe1e46')).rejects.toThrow('SOME_ERROR');
  });
});

export function getTimeToLiveEpoch(ttlMinutes: number): number {
  return Math.floor((Date.now() + ttlMinutes * 60 * 1000) / 1000);
}
