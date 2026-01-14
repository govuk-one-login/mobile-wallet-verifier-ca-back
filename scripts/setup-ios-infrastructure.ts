import { SecretsManagerClient, CreateSecretCommand, GetSecretValueCommand, ResourceExistsException } from '@aws-sdk/client-secrets-manager';
import { generateECDSAKeyPair, createRootCA } from '../src/lambdas/generate-mock-issue-cert/mock-utils/crypto-utils.ts';

const REGION = 'eu-west-2';

export const IOS_DEVICE_KEYS_SECRET = 'ios-device-keys-test';
export const IOS_ROOT_CA_SECRET = 'ios-root-ca-test';
export const IOS_INTERMEDIATE_CA_SECRET = 'ios-intermediate-ca-test';

async function setupIOSInfrastructure() {
  const client = new SecretsManagerClient({ region: REGION });

  console.log('Generating iOS device keys...');
  const deviceKeys = generateECDSAKeyPair('prime256v1');

  console.log('Generating iOS root CA...');
  const rootCAKeys = generateECDSAKeyPair('prime256v1');
  const rootCACert = await createRootCA(rootCAKeys);

  console.log('Generating iOS intermediate CA keys...');
  const intermediateKeys = generateECDSAKeyPair('prime256v1');

  await createSecretIfNotExists(client, IOS_DEVICE_KEYS_SECRET, deviceKeys);
  await createSecretIfNotExists(client, IOS_ROOT_CA_SECRET, { keyPair: rootCAKeys, certificatePem: rootCACert });
  await createSecretIfNotExists(client, IOS_INTERMEDIATE_CA_SECRET, intermediateKeys);

  console.log('✅ iOS infrastructure setup complete');
}

async function createSecretIfNotExists(client: SecretsManagerClient, name: string, value: any) {
  try {
    await client.send(new GetSecretValueCommand({ SecretId: name }));
    console.log(`✓ ${name} already exists, skipping`);
  } catch (error: any) {
    if (error.name === 'ResourceNotFoundException') {
      console.log(`Creating ${name}...`);
      await client.send(new CreateSecretCommand({ Name: name, SecretString: JSON.stringify(value) }));
      console.log(`✓ ${name} created`);
    } else {
      throw error;
    }
  }
}

setupIOSInfrastructure().catch((error) => {
  console.error('❌ Error setting up iOS infrastructure:', error);
  process.exit(1);
});
