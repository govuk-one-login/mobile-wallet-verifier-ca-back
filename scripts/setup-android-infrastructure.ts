#!/usr/bin/env tsx

import { KeyManager } from '../src/lambdas/generate-mock-issue-cert/mock-utils/key-manager.ts';
import { generateECDSAKeyPair, createRootCA } from '../src/lambdas/generate-mock-issue-cert/mock-utils/crypto-utils.ts';

export const DEVICE_KEYS_SECRET = 'android-device-keys-9';
export const PLAY_INTEGRITY_KEYS_SECRET = 'android-play-integrity-keys-9';
export const ROOT_CA_SECRET = 'android-root-ca-9';
export const INTERMEDIATE_CA_SECRET = 'android-intermediate-ca-9';
export const LEAF_CA_SECRET = 'android-leaf-ca-9';

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
    
    // Generate device keys (ECDSA P-256 for Android attestation)
    console.log('Generating Android device keys...');
    const deviceKeys = generateECDSAKeyPair('prime256v1');
    await keyManager.storeKeyPair(DEVICE_KEYS_SECRET, deviceKeys);
    
    // Generate Play Integrity keys
    console.log('Generating Play Integrity keys...');
    const playIntegrityKeys = generateECDSAKeyPair('prime256v1');
    await keyManager.storeKeyPair(PLAY_INTEGRITY_KEYS_SECRET, playIntegrityKeys);
    
    // Generate Root CA
    console.log('Generating Android Root CA...');
    const rootCAKeys = generateECDSAKeyPair('prime256v1');
    const rootCACert = await createRootCA(rootCAKeys);
    
    await keyManager.storeCA(ROOT_CA_SECRET, {
      keyPair: rootCAKeys,
      certificatePem: rootCACert
    });
    
    // Generate Intermediate CA keys
    console.log('Generating Intermediate CA keys...');
    const intermediateCAKeys = generateECDSAKeyPair('prime256v1');
    await keyManager.storeKeyPair(INTERMEDIATE_CA_SECRET, intermediateCAKeys);
    
    // Generate Leaf CA keys
    console.log('Generating Leaf CA keys...');
    const leafCAKeys = generateECDSAKeyPair('prime256v1');
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