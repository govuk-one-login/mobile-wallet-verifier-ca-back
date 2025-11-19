import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { randomUUID } from 'crypto';
import type { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { createErrorResponse, createSuccessResponse } from '../../../common/responseUtils';

const NONCE_TTL_SECONDS = 300; // 5 minutes
const MILLISECONDS_PER_SECOND = 1000;

const dynamoClient = new DynamoDBClient({});

export const handler = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  
  if (event.httpMethod !== 'POST' || event.path !== '/nonce') {
    return createErrorResponse(404, 'Not Found');
  }

  const tableName = process.env.NONCE_TABLE_NAME;
  if (!tableName) {
    return createErrorResponse(500, 'Configuration error');
  }

  try {
    // Generate UUIDv4 as nonce value (36-character string with lowercase hex)
    const nonceValue = randomUUID().toLowerCase();
    const currentTime = Math.floor(Date.now() / MILLISECONDS_PER_SECOND);
    const timeToLive = currentTime + NONCE_TTL_SECONDS;
    const expiresAt = new Date((currentTime + NONCE_TTL_SECONDS) * MILLISECONDS_PER_SECOND).toISOString();

    const putCommand = new PutItemCommand({
      TableName: tableName,
      Item: {
        nonceValue: { S: nonceValue },
        timeToLive: { N: timeToLive.toString() }
      }
    });

    await dynamoClient.send(putCommand);
    
    return createSuccessResponse(context, nonceValue, expiresAt);
    
  } catch (error) {
    return createErrorResponse(500, 'An unexpected error occurred while generating the nonce.', `https://api.example.com/trace/${context.awsRequestId}`);
  }
};