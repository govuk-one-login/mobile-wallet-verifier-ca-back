import { randomUUID } from 'crypto';
import { Logger } from '@aws-lambda-powertools/logger';
import { KeyManager } from './mock-utils/key-manager';
import { AndroidDeviceSimulator } from './mock-utils/android-mock';
import { IOSDeviceSimulator } from './mock-utils/ios-mock';
import { DEVICE_KEYS_SECRET } from '../../../scripts/setup-android-infrastructure';

const logger = new Logger();

interface MockRequest {
  platform: string;
  nonce: string;
  csrPem: string;
  keyAttestationChain?: string[];
  playIntegrityToken?: string;
  appAttest?: {
    keyId: string;
    attestationObject: string;
    clientDataJSON: string;
  };
}

export const handler = async (inputNonce?: string, platform: 'android' | 'ios' = 'android'): Promise<MockRequest> => {
  logger.info('Generating mock issue cert payload', { platform });

  const nonce = inputNonce || randomUUID().toLowerCase();

  if (platform === 'ios') {
    const iosSimulator = new IOSDeviceSimulator();
    const payload = await iosSimulator.generateMockRequest(nonce);
    return {
      platform: 'ios',
      nonce: payload.nonce,
      csrPem: payload.csrPem,
      appAttest: {
        keyId: payload.keyId,
        attestationObject: payload.attestationObject,
        clientDataJSON: payload.clientDataJSON,
      },
    };
  }

  const keyManager = new KeyManager();
  const keyPair = await keyManager.getKeyPair(DEVICE_KEYS_SECRET);

  if (!keyPair) {
    throw new Error('Key pair not found. Run setup-android-infrastructure.ts first.');
  }

  const androidSimulator = new AndroidDeviceSimulator();
  const payload = await androidSimulator.generateMockRequest(nonce);

  return { ...payload, platform: 'android' };
};

// Execute when run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const nonce = process.argv[2];
  const platform = (process.argv[3] as 'android' | 'ios') || 'android';
  handler(nonce, platform)
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
