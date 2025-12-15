import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { KeyPair } from './crypto-utils.ts';

const REGION = 'eu-west-2';

export const IOS_DEVICE_KEYS_SECRET = 'ios-device-keys-test';
export const IOS_ROOT_CA_SECRET = 'ios-root-ca-test';
export const IOS_INTERMEDIATE_CA_SECRET = 'ios-intermediate-ca-test';

export class IOSKeyProvider {
  private client: SecretsManagerClient;

  constructor() {
    this.client = new SecretsManagerClient({ region: REGION });
  }

  async getDeviceKeys(): Promise<KeyPair> {
    const response = await this.client.send(new GetSecretValueCommand({ SecretId: IOS_DEVICE_KEYS_SECRET }));
    if (!response.SecretString) throw new Error('Device keys not found');
    return JSON.parse(response.SecretString);
  }

  async getRootCA(): Promise<{ keyPair: KeyPair; certificatePem: string }> {
    const response = await this.client.send(new GetSecretValueCommand({ SecretId: IOS_ROOT_CA_SECRET }));
    if (!response.SecretString) throw new Error('Root CA not found');
    return JSON.parse(response.SecretString);
  }

  async getIntermediateCAKeys(): Promise<KeyPair> {
    const response = await this.client.send(new GetSecretValueCommand({ SecretId: IOS_INTERMEDIATE_CA_SECRET }));
    if (!response.SecretString) throw new Error('Intermediate CA keys not found');
    return JSON.parse(response.SecretString);
  }
}
