import { createSign, randomUUID } from 'node:crypto';
import {
  getOrCreateRSAKeys,
  FIREBASE_KID,
} from '../common/mock-utils/key-pair-manager';
import { dependencies } from './mock-issue-cert-handler-dependencies';
import { getGenerateMockIssueCertRequestConfig } from './mock-issue-cert-config';

export interface FirebaseAppCheckPayload {
  sub: string;
  aud: string[];
  provider: string;
  iss: string;
  exp: number;
  iat: number;
  jti: string;
}

export class FirebaseAppCheckSigner {
  private region?: string;

  constructor(region?: string) {
    this.region = region;
  }

  async generateDebugToken(
    appId: string = 'org.multipaz.identityreader',
    scenario?: string,
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    const sub =
      scenario === 'invalid-sub' ? 'invalid-jwt' : `1:1111:ios:${appId}`;

    const configResult = getGenerateMockIssueCertRequestConfig(
      dependencies.env,
    );
    if (configResult.isError) {
      throw new Error('Failed to load configuration');
    }

    const payload: FirebaseAppCheckPayload = {
      sub,
      aud: ['projects/mock-verifier-app'],
      provider: 'custom',
      iss: configResult.value.FIREBASE_JWKS_URI,
      exp: now + 3600,
      iat: now,
      jti: randomUUID(),
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
