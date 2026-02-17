import { createSign, generateKeyPairSync } from 'node:crypto';
import { KeyManager } from './key-manager';

const KID = 'firebase-appcheck-debug';
const FIREBASE_APPCHECK_SECRET =
  process.env.FIREBASE_KEYS_SECRET ||
  'mobile-wallet-verifier-ca-back-dev-mock-firebase-appcheck-keys';

export interface FirebaseAppCheckPayload {
  iss: string;
  sub: string;
  aud: string[];
  exp: number;
  iat: number;
  app_id: string;
}

export class FirebaseAppCheckSigner {
  private keyManager: KeyManager;

  constructor(region?: string) {
    console.log('FirebaseAppCheckSigner constructor', {
      region,
      secretName: FIREBASE_APPCHECK_SECRET,
      envVars: {
        FIREBASE_KEYS_SECRET: process.env.FIREBASE_KEYS_SECRET,
        DEVICE_KEYS_SECRET: process.env.DEVICE_KEYS_SECRET,
        AWS_REGION: process.env.AWS_REGION,
      },
    });
    this.keyManager = new KeyManager(region);
  }

  private async getOrCreateRSAKeys() {
    console.log(
      'Getting or creating RSA keys from secret:',
      FIREBASE_APPCHECK_SECRET,
    );

    try {
      let keyPair = await this.keyManager.getKeyPair(FIREBASE_APPCHECK_SECRET);

      // Check if we got placeholder values or no keys
      if (
        !keyPair ||
        keyPair.privateKeyPem === 'PLACEHOLDER' ||
        keyPair.publicKeyPem === 'PLACEHOLDER'
      ) {
        console.log(
          'No valid keys found (placeholder or missing), generating new RSA key pair',
        );
        // Generate RSA key pair for JWT signing
        const { privateKey, publicKey } = generateKeyPairSync('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });

        keyPair = { privateKeyPem: privateKey, publicKeyPem: publicKey };
        console.log('Updating secret with new key pair in Secrets Manager');
        await this.keyManager.updateKeyPair(FIREBASE_APPCHECK_SECRET, keyPair);
        console.log('Key pair updated successfully');
      } else {
        console.log('Using existing valid key pair from Secrets Manager');
      }

      return keyPair;
    } catch (error) {
      console.error('Error in getOrCreateRSAKeys:', error);
      throw error;
    }
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
      kid: KID,
    };

    const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
      'base64url',
    );
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
      'base64url',
    );
    const data = `${encodedHeader}.${encodedPayload}`;

    const keyPair = await this.getOrCreateRSAKeys();
    const sign = createSign('SHA256');
    sign.update(data);
    const signature = sign.sign(keyPair.privateKeyPem, 'base64url');

    return `${data}.${signature}`;
  }

  async generateJWKS() {
    console.log('Starting JWKS generation');

    try {
      const keyPair = await this.getOrCreateRSAKeys();
      console.log('Got key pair, validating PEM format');

      // Validate and clean PEM format
      const publicKeyPem = keyPair.publicKeyPem.trim();
      if (!publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----')) {
        throw new Error('Invalid public key PEM format - missing header');
      }
      if (!publicKeyPem.endsWith('-----END PUBLIC KEY-----')) {
        throw new Error('Invalid public key PEM format - missing footer');
      }

      console.log('PEM format validated, creating public key object');
      const { createPublicKey } = await import('node:crypto');
      const publicKey = createPublicKey(publicKeyPem);
      console.log('Public key object created');

      const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
      console.log('JWK exported', { kty: jwk.kty, alg: 'RS256', kid: KID });

      const jwks = {
        keys: [
          {
            kty: jwk.kty,
            use: 'sig',
            kid: KID,
            alg: 'RS256',
            n: jwk.n,
            e: jwk.e,
          },
        ],
      };

      console.log('JWKS generated successfully', {
        keysCount: jwks.keys.length,
      });
      return jwks;
    } catch (error) {
      console.error('Error in generateJWKS:', error);
      throw error;
    }
  }

  async getPublicKeyPem(): Promise<string> {
    const keyPair = await this.getOrCreateRSAKeys();
    return keyPair.publicKeyPem;
  }

  getKid(): string {
    return KID;
  }
}
