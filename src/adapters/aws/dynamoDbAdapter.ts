import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DeleteCommand, DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { NonceTableItem } from '../../types/NonceTableItem';
import { logger } from '../../logging/logger';

const dynamoDBClient = new DynamoDBClient({});
const documentClient = DynamoDBDocumentClient.from(dynamoDBClient);

export async function saveNonce(tableName: string, item: NonceTableItem): Promise<void> {
  const command = new PutCommand({
    TableName: tableName,
    Item: item,
  });
  await documentClient.send(command);
}

export async function getNonce(tableName: string, nonceValue: string): Promise<NonceTableItem | undefined> {
  const command = new GetCommand({
    TableName: tableName,
    Key: {
      nonceValue,
    },
  });

  const response = await documentClient.send(command);

  const item = response.Item;
  if (!item) {
    logger.error(`Could not find Nonce: ${nonceValue}`);
    return undefined;
  }
  return item as NonceTableItem;
}

export async function deleteNonce(tableName: string, nonceValue: string): Promise<void> {
  const command = new DeleteCommand({
    TableName: tableName,
    Key: {
      nonceValue,
    },
  });
  await documentClient.send(command);
}
