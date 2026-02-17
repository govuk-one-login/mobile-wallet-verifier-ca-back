import {
  SecretsManagerClient,
  GetSecretValueCommand,
  CreateSecretCommand,
  UpdateSecretCommand,
} from '@aws-sdk/client-secrets-manager';

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
    console.log('KeyManager constructor', { region });
    this.client = new SecretsManagerClient({ region });
  }

  async getKeyPair(secretName: string): Promise<KeyPair | null> {
    console.log('Getting key pair from Secrets Manager', { secretName });

    try {
      const command = new GetSecretValueCommand({ SecretId: secretName });
      const response = await this.client.send(command);
      console.log('Secrets Manager response received', {
        hasSecretString: !!response.SecretString,
      });

      if (response.SecretString) {
        const data = JSON.parse(response.SecretString);
        const keyPair = data.keyPair || data;

        // Log PEM format for debugging
        console.log('Key pair structure:', {
          hasPrivateKey: !!keyPair.privateKeyPem,
          hasPublicKey: !!keyPair.publicKeyPem,
          publicKeyStart: keyPair.publicKeyPem?.substring(0, 50),
          publicKeyEnd: keyPair.publicKeyPem?.substring(-50),
        });

        return keyPair;
      }
    } catch (error) {
      console.log('Error getting key pair', {
        error: error instanceof Error ? error.message : String(error),
        errorName: error instanceof Error ? error.name : 'Unknown',
      });

      if (
        error instanceof Error &&
        error.name !== 'ResourceNotFoundException'
      ) {
        throw error;
      }
    }
    console.log('No key pair found, returning null');
    return null;
  }

  async storeKeyPair(secretName: string, keyPair: KeyPair): Promise<void> {
    console.log('Storing key pair in Secrets Manager', { secretName });

    try {
      await this.client.send(
        new CreateSecretCommand({
          Name: secretName,
          SecretString: JSON.stringify({ keyPair }),
          Description:
            'ECDSA key pair for CSR generation and Play Integrity token signing',
        }),
      );
      console.log('Key pair stored successfully');
    } catch (error) {
      console.error('Error storing key pair', { error });
      throw error;
    }
  }

  async updateKeyPair(secretName: string, keyPair: KeyPair): Promise<void> {
    console.log('Updating key pair in Secrets Manager', { secretName });

    try {
      await this.client.send(
        new UpdateSecretCommand({
          SecretId: secretName,
          SecretString: JSON.stringify({ keyPair }),
        }),
      );
      console.log('Key pair updated successfully');
    } catch (error) {
      console.error('Error updating key pair', { error });
      throw error;
    }
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
    } catch (error) {
      if (
        error instanceof Error &&
        error.name !== 'ResourceNotFoundException'
      ) {
        throw error;
      }
    }
    return null;
  }
}
