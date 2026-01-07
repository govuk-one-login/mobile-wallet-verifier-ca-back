import { randomUUID } from 'crypto';
import { Logger } from '@aws-lambda-powertools/logger';
import { KeyManager } from './mock-utils/key-manager';
import { AndroidDeviceSimulator } from './mock-utils/android-mock';
import { DEVICE_KEYS_SECRET } from '../../../scripts/setup-android-infrastructure';

const logger = new Logger();

interface MockRequest {
  nonce: string;
  csrPem: string;
  keyAttestationChain: string[];
  playIntegrityToken: string;
  platform: string;
}

export const handler = async (inputNonce?: string): Promise<MockRequest> => {
  logger.info('Generating mock issue cert payload');

  const keyManager = new KeyManager();
  const keyPair = await keyManager.getKeyPair(DEVICE_KEYS_SECRET);

  if (!keyPair) {
    throw new Error('Key pair not found. Run setup-android-infrastructure.ts first.');
  }

  const deviceSimulator = new AndroidDeviceSimulator();
  const nonce = inputNonce || randomUUID().toLowerCase();

  const payload = await deviceSimulator.generateMockRequest(nonce);

  return {
    ...payload,
    platform: 'android',
  };
};

// Execute when run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const nonce = process.argv[2]; // Get nonce from command line argument
  handler(nonce)
    .then((result) => {
      console.log('✅ Mock certificate generator invoked successfully');
      console.log('Generated mock request:');
      console.log(JSON.stringify(result, null, 2));
    })
    .catch((error) => {
      console.error('❌ Error invoking mock certificate generator:', error);
      process.exit(1);
    });
}
