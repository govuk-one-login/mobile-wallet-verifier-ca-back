import { Logger } from '@aws-lambda-powertools/logger';
import { KeyManager } from './mock-utils/key-manager.ts';
import { AndroidDeviceSimulator } from './mock-utils/android-mock.ts';
import { DEVICE_KEYS_SECRET } from '../../../scripts/setup-android-infrastructure.ts';

const logger = new Logger();

interface MockRequest {
  nonce: string;
  csrPem: string;
  keyAttestationChain: string[];
  playIntegrityToken: string;
  platform: string;
}

export const handler = async (): Promise<MockRequest> => {
  logger.info('Generating mock issue cert payload');

  const keyManager = new KeyManager();
  const keyPair = await keyManager.getKeyPair(DEVICE_KEYS_SECRET);
  
  if (!keyPair) {
    throw new Error('Key pair not found. Run setup-android-infrastructure.ts first.');
  }

  const deviceSimulator = new AndroidDeviceSimulator();
  const nonce = '3c18b3e0-e4b2-4f47-a697-c0c7b8d2d68b';
  
  const payload = await deviceSimulator.generateMockRequest(nonce);
  
  return {
    ...payload,
    platform: 'android'
  };
};

// Execute when run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  handler()
    .then(result => {
      console.log('✅ Mock certificate generator invoked successfully');
      console.log('Generated mock request:');
      console.log(JSON.stringify(result, null, 2));
    })
    .catch(error => {
      console.error('❌ Error invoking mock certificate generator:', error);
      process.exit(1);
    });
}