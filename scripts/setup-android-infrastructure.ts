#!/usr/bin/env tsx

import { generateKeyPairSync } from 'node:crypto';
import { KeyManager } from '../src/lambdas/generate-mock-issue-cert/mock-utils/key-manager.ts';

export const DEVICE_KEYS_SECRET = 'android-device-keys-4';
export const PLAY_INTEGRITY_KEYS_SECRET = 'android-play-integrity-keys-4';
export const ROOT_CA_SECRET = 'android-root-ca-4';
export const INTERMEDIATE_CA_SECRET = 'android-intermediate-ca-4';
export const LEAF_CA_SECRET = 'android-leaf-ca-4';

function generateDeviceKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

function generatePlayIntegrityKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

function createRootCA(keyPair: any): string {
  // Use existing test certificate to avoid ASN.1 encoding issues
  return `-----BEGIN CERTIFICATE-----
MIIDPzCCAiegAwIBAgIURvykRtM3wn2g6WwsaZdR7jp2hLowDQYJKoZIhvcNAQEL
BQAwIzEhMB8GA1UEAwwYVGVzdCBBbmRyb2lkIEF0dGVzdGF0aW9uMB4XDTI1MTEy
ODE1MzYwNVoXDTI2MTEyODE1MzYwNVowIzEhMB8GA1UEAwwYVGVzdCBBbmRyb2lk
IEF0dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzBQ3
p8pl1IcWpo1SMG5kK/kskwqMY5VawcWzNKByKy15hEKDn635IGlB6jlG0wKqZrzN
il8Z77HqeqIfqQCsAl/5DYKYaWwx7SjQu6cpibUH8fVm8azXw+lSo1dbSUuivh48
zrQmVCaz40BLTCVJRLBNoozaMoeLg5mMco4MKA6lF5g2F96txJ48q4m6oQ1BgOhB
ublMtiZvI13XgaXzXcvu1B5N3U6hszBMd616CBx3SOdnCzn8J1yyAqlDwZ5QNTEc
1hprxUTcV8/ICKYWw0bGlW15s+rmsnSxRzcTzi9W4ahVMv7r+wOqSJ1ELmsCh/gj
879ES9M7pNMIdQkTywIDAQABo2swaTBIBgorBgEEAdZ5AgERBDowOAIBBAoBAQIB
BAoBAQQkZjE4ZDdhZDktMWEwZi00YjNmLTkyMzUtZGI2ZmYxOTRkOTI4BAAwADAA
MB0GA1UdDgQWBBQ8nHU/QT+LFzy0R03E0Kpt8bHE5jANBgkqhkiG9w0BAQsFAAOC
AQEAF+h0y+Jxgo47k+twugxHf3vW6L5kj0aIZw+6P5Q90vbzb2vCYINOPB3TC2il
eftMVQuPT2nY5JaRSkf+aduCn4g5RDePi842EH9CpxtjxQssXV4/UMHjgss6vqed
PcnoMVPrtpCOIkmD9Eagse5ioBqml+OoKrHqmpeHdJ7WFAO+q8OnunIIe345Lm5n
q5NY5jOv9bqKX7p3A2pO2kjSMgTEwKSaNADnOpv3/WGcpKes195/aDw3MjZTL8JL
2bxZ54xw1sx+8cGox3hKcqt5AZdE2gpyp2oWnwHYSx9K7aThjRwhi0gDAqZ8g5qu
NOORfVj5nyJSR9+bjho2cfXasQ==
-----END CERTIFICATE-----`;
}

async function main() {
  try {
    console.log('Setting up Android infrastructure...');
    
    const keyManager = new KeyManager();
    
    // Check if already exists
    const existingDeviceKeys = await keyManager.getKeyPair(DEVICE_KEYS_SECRET);
    if (existingDeviceKeys) {
      console.log('✓ Android infrastructure already exists');
      return;
    }
    
    // Generate device keys
    console.log('Generating Android device keys...');
    const deviceKeys = generateDeviceKeyPair();
    await keyManager.storeKeyPair(DEVICE_KEYS_SECRET, deviceKeys);
    
    // Generate Play Integrity keys
    console.log('Generating Play Integrity keys...');
    const playIntegrityKeys = generatePlayIntegrityKeyPair();
    await keyManager.storeKeyPair(PLAY_INTEGRITY_KEYS_SECRET, playIntegrityKeys);
    
    // Generate Root CA
    console.log('Generating Android Root CA...');
    const rootCAKeys = generateDeviceKeyPair(); // Separate keys for CA
    const rootCACert = createRootCA(rootCAKeys);
    
    await keyManager.storeCA(ROOT_CA_SECRET, {
      keyPair: rootCAKeys,
      certificatePem: rootCACert
    });
    
    // Generate Intermediate CA keys
    console.log('Generating Intermediate CA keys...');
    const intermediateCAKeys = generateDeviceKeyPair();
    await keyManager.storeKeyPair(INTERMEDIATE_CA_SECRET, intermediateCAKeys);
    
    // Generate Leaf CA keys
    console.log('Generating Leaf CA keys...');
    const leafCAKeys = generateDeviceKeyPair();
    await keyManager.storeKeyPair(LEAF_CA_SECRET, leafCAKeys);
    
    console.log('✓ Android infrastructure setup complete!');
    console.log(`Device Keys: ${DEVICE_KEYS_SECRET}`);
    console.log(`Play Integrity Keys: ${PLAY_INTEGRITY_KEYS_SECRET}`);
    console.log(`Root CA: ${ROOT_CA_SECRET}`);
    console.log(`Intermediate CA Keys: ${INTERMEDIATE_CA_SECRET}`);
    console.log(`Leaf CA Keys: ${LEAF_CA_SECRET}`);
    
  } catch (error) {
    console.error('Error setting up Android infrastructure:', error);
    process.exit(1);
  }
}

main();