import { createSign, randomUUID } from 'node:crypto';
import {
  getOrCreateRSAKeys,
  FIREBASE_KID,
} from '../common/mock-utils/key-pair-manager';
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
  private readonly env: NodeJS.ProcessEnv;

  constructor(env: NodeJS.ProcessEnv = process.env) {
    this.env = env;
  }

  async generateDebugToken(
    appId: string = 'org.multipaz.identityreader',
    scenario?: string,
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    const sub =
      scenario === 'invalid-sub' ? 'invalid-jwt' : `1:1111:ios:${appId}`;

    const configResult = getGenerateMockIssueCertRequestConfig(this.env);
    if (configResult.isError) {
      throw new Error('Failed to load configuration');
    }

    const firebaseJwksSecret = configResult.value.FIREBASE_APPCHECK_JWKS_SECRET;
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

    const keyPair = await getOrCreateRSAKeys(firebaseJwksSecret);
    const sign = createSign('SHA256');
    sign.update(data);
    const signature = sign.sign(keyPair.privateKeyPem, 'base64url');

    return `${data}.${signature}`;
  }

  async getPublicKeyPem(firebaseJwksSecret: string): Promise<string> {
    const keyPair = await getOrCreateRSAKeys(firebaseJwksSecret);
    return keyPair.publicKeyPem;
  }
}
