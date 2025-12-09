import { SecretsManagerClient, GetSecretValueCommand, CreateSecretCommand } from '@aws-sdk/client-secrets-manager';

export interface KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export interface StoredCA {
  keyPair: KeyPair;
  certificatePem: string;
}

export class KeyManager {
  private client: SecretsManagerClient;

  constructor(region = 'eu-west-2') {
    this.client = new SecretsManagerClient({ region });
  }

  async getKeyPair(secretName: string): Promise<KeyPair | null> {
    try {
      const command = new GetSecretValueCommand({ SecretId: secretName });
      const response = await this.client.send(command);

      if (response.SecretString) {
        const data = JSON.parse(response.SecretString);
        return data.keyPair || data;
      }
    } catch (error: any) {
      if (error.name !== 'ResourceNotFoundException') {
        throw error;
      }
    }
    return null;
  }

  async storeKeyPair(secretName: string, keyPair: KeyPair): Promise<void> {
    await this.client.send(
      new CreateSecretCommand({
        Name: secretName,
        SecretString: JSON.stringify({ keyPair }),
        Description: 'ECDSA key pair for CSR generation and Play Integrity token signing',
      }),
    );
  }

  async storeCA(secretName: string, ca: StoredCA): Promise<void> {
    await this.client.send(
      new CreateSecretCommand({
        Name: secretName,
        SecretString: JSON.stringify(ca),
        Description: 'Root CA certificate and key pair',
      }),
    );
  }

  async getCA(secretName: string): Promise<StoredCA | null> {
    try {
      const command = new GetSecretValueCommand({ SecretId: secretName });
      const response = await this.client.send(command);

      if (response.SecretString) {
        return JSON.parse(response.SecretString);
      }
    } catch (error: any) {
      if (error.name !== 'ResourceNotFoundException') {
        throw error;
      }
    }
    return null;
  }
}
