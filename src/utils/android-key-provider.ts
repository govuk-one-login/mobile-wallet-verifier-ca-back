import { KeyManager } from './key-manager.js';
import { DEVICE_KEYS_SECRET, INTERMEDIATE_CA_SECRET, LEAF_CA_SECRET, PLAY_INTEGRITY_KEYS_SECRET, ROOT_CA_SECRET } from '../../scripts/setup-android-infrastructure.ts';

export class AndroidKeyProvider {
  private keyManager: KeyManager;
  //private readonly DEVICE_KEYS_SECRET = process.env.DEVICE_KEYS_SECRET;
  //private readonly PLAY_INTEGRITY_KEYS_SECRET = process.env.PLAY_INTEGRITY_KEYS_SECRET;
  //private readonly ROOT_CA_SECRET = process.env.ROOT_CA_SECRET;
  //private readonly INTERMEDIATE_CA_SECRET = process.env.INTERMEDIATE_CA_SECRET;
  //private readonly LEAF_CA_SECRET = process.env.LEAF_CA_SECRET;

  constructor() {
    this.keyManager = new KeyManager();
  }

  async getDeviceKeys() {
    const keys = await this.keyManager.getKeyPair(DEVICE_KEYS_SECRET!);
    if (!keys) throw new Error('Device keys not found. Run setup-android-infrastructure.ts first.');
    return keys;
  }

  async getPlayIntegrityKeys() {
    const keys = await this.keyManager.getKeyPair(PLAY_INTEGRITY_KEYS_SECRET!);
    if (!keys) throw new Error('Play Integrity keys not found. Run setup-android-infrastructure.ts first.');
    return keys;
  }

  async getRootCA() {
    const ca = await this.keyManager.getCA(ROOT_CA_SECRET!);
    if (!ca) throw new Error('Root CA not found. Run setup-android-infrastructure.ts first.');
    return ca;
  }

  async getIntermediateCAKeys() {
    const keys = await this.keyManager.getKeyPair(INTERMEDIATE_CA_SECRET!);
    if (!keys) throw new Error('Intermediate CA keys not found. Run setup-android-infrastructure.ts first.');
    return keys;
  }

  async getLeafCAKeys() {
    const keys = await this.keyManager.getKeyPair(LEAF_CA_SECRET!);
    if (!keys) throw new Error('Leaf CA keys not found. Run setup-android-infrastructure.ts first.');
    return keys;
  }
}