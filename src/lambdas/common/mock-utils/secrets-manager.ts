import {
  SecretsManagerClient,
  GetSecretValueCommand,
  UpdateSecretCommand,
} from '@aws-sdk/client-secrets-manager';
import { KeyPair } from './key-pair-manager';
import { logger } from '../logger/logger';

export class SecretsManagerKeyStore {
  private readonly client: SecretsManagerClient;

  constructor(region = 'eu-west-2') {
    logger.info('SecretsManagerKeyStore constructor', { region });
    this.client = new SecretsManagerClient({ region });
  }

  async getKeyPair(secretName: string): Promise<KeyPair | null> {
    logger.info('Getting key pair from Secrets Manager', { secretName });

    try {
      const command = new GetSecretValueCommand({ SecretId: secretName });
      const response = await this.client.send(command);
      logger.info('Secrets Manager response received', {
        hasSecretString: !!response.SecretString,
      });

      if (response.SecretString) {
        const data = JSON.parse(response.SecretString);
        const keyPair = data.keyPair;
        logger.info('Key pair retrieved successfully');
        return keyPair;
      }
    } catch (error) {
      logger.error('Error getting key pair', {
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
    logger.info('No key pair found, returning null');
    return null;
  }

  async updateKeyPair(secretName: string, keyPair: KeyPair): Promise<void> {
    logger.info('Updating key pair in Secrets Manager', { secretName });

    try {
      await this.client.send(
        new UpdateSecretCommand({
          SecretId: secretName,
          SecretString: JSON.stringify({ keyPair }),
        }),
      );
      logger.info('Key pair updated successfully');
    } catch (error) {
      logger.error('Error updating key pair', { error });
      throw error;
    }
  }
}
