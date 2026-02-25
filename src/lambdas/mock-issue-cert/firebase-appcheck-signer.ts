import { createSign } from 'node:crypto';
import {
  getOrCreateRSAKeys,
  FIREBASE_KID,
} from '../common/mock-utils/rsa-key-manager';

export interface FirebaseAppCheckPayload {
  iss: string;
  sub: string;
  aud: string[];
  exp: number;
  iat: number;
  app_id: string;
}

export class FirebaseAppCheckSigner {
  private region?: string;

  constructor(region?: string) {
    this.region = region;
  }

  async generateDebugToken(
    appId: string = 'org.multipaz.identityreader',
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    const payload: FirebaseAppCheckPayload = {
      iss: 'https://firebase.google.com/project/mock-project',
      sub: appId,
      aud: [`projects/mock-project/apps/${appId}`],
      exp: now + 3600, // 1 hour
      iat: now,
      app_id: appId,
    };

    const header = {
      alg: 'RS256',
      typ: 'JWT',
      kid: FIREBASE_KID,
    };

    const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
      'base64url',
    );
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
      'base64url',
    );
    const data = `${encodedHeader}.${encodedPayload}`;

    const keyPair = await getOrCreateRSAKeys(this.region);
    const sign = createSign('SHA256');
    sign.update(data);
    const signature = sign.sign(keyPair.privateKeyPem, 'base64url');

    return `${data}.${signature}`;
  }

  async getPublicKeyPem(): Promise<string> {
    const keyPair = await getOrCreateRSAKeys(this.region);
    return keyPair.publicKeyPem;
  }
}
