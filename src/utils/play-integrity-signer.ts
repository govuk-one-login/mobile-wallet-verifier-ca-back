import { createSign } from 'node:crypto';
import { KeyManager } from './key-manager.js';

export interface PlayIntegrityPayload {
  requestDetails: {
    requestPackageName: string;
    timestampMillis: string;
    nonce: string;
  };
  appIntegrity: {
    appRecognitionVerdict: string;
    packageName: string;
    certificateSha256Digest: string[];
    versionCode: string;
  };
  deviceIntegrity: {
    deviceRecognitionVerdict: string[];
  };
  accountDetails: {
    appLicensingVerdict: string;
  };
}

export class PlayIntegritySigner {
  private keyManager: KeyManager;

  constructor(region?: string) {
    this.keyManager = new KeyManager(region);
  }

  async signToken(payload: PlayIntegrityPayload, secretName: string): Promise<string> {
    const keyPair = await this.keyManager.getKeyPair(secretName);
    if (!keyPair) {
      throw new Error(`Key pair not found: ${secretName}`);
    }
    
    const header = {
      alg: 'RS256',
      typ: 'JWT',
      kid: secretName // Add key ID to match JWKS requirements
    };

    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    
    const data = `${encodedHeader}.${encodedPayload}`;
    
    const sign = createSign('RSA-SHA256');
    sign.update(data);
    const signature = sign.sign(keyPair.privateKeyPem, 'base64url');
    
    return `${data}.${signature}`;
  }
}