import { KeyManager } from './key-manager.ts';
import {
  DEVICE_KEYS_SECRET,
  INTERMEDIATE_CA_SECRET,
  ROOT_CA_SECRET,
} from '../../../../scripts/setup-android-infrastructure.ts';

export class AndroidKeyProvider {
  private keyManager = new KeyManager();

  private async getKeyPairOrThrow(secretName: string, keyType: string) {
    const keys = await this.keyManager.getKeyPair(secretName);
    if (!keys)
      throw new Error(
        `${keyType} not found. Run setup-android-infrastructure.ts first.`,
      );
    return keys;
  }

  async getDeviceKeys() {
    return this.getKeyPairOrThrow(DEVICE_KEYS_SECRET, 'Device keys');
  }

  async getRootCA() {
    const ca = await this.keyManager.getCA(ROOT_CA_SECRET);
    if (!ca)
      throw new Error(
        'Root CA not found. Run setup-android-infrastructure.ts first.',
      );
    return ca;
  }

  async getIntermediateCAKeys() {
    return this.getKeyPairOrThrow(
      INTERMEDIATE_CA_SECRET,
      'Intermediate CA keys',
    );
  }
}
