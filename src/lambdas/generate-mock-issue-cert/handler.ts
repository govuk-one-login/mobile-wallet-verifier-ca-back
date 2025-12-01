import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import { KeyManager } from '../../utils/key-manager.ts';
import { AndroidDeviceSimulator } from '../../utils/android-mock.ts';
import { DEVICE_KEYS_SECRET } from '../../../scripts/setup-android-infrastructure.ts';

const logger = new Logger();


export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    logger.info('Generating mock issue cert payload');

    const keyManager = new KeyManager();
    const keyPair = await keyManager.getKeyPair(DEVICE_KEYS_SECRET);
    
    if (!keyPair) {
      throw new Error('Key pair not found. Run setup-android-infrastructure.ts first.');
    }

    // Use Android device simulator for more realistic behavior
    const deviceSimulator = new AndroidDeviceSimulator();
    const nonce = '3c18b3e0-e4b2-4f47-a697-c0c7b8d2d68b';
    
    const payload = await deviceSimulator.generateMockRequest(nonce);
    
    const response = {
      ...payload,
      platform: 'android'
    };

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify(response)
    };

  } catch (error) {
    logger.error('Error generating mock issue cert payload', { error });
    
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        error: 'Internal server error',
        message: error instanceof Error ? error.message : 'Unknown error'
      })
    };
  }
};