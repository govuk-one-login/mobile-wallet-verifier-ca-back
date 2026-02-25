import { createPublicKey } from 'node:crypto';
import {
  getOrCreateRSAKeys,
  FIREBASE_KID,
} from '../common/mock-utils/rsa-key-manager';

export async function generateJWKS(region?: string) {
  const keyPair = await getOrCreateRSAKeys(region);

  const publicKeyPem = keyPair.publicKeyPem.trim();
  if (!publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----')) {
    throw new Error('Invalid public key PEM format - missing header');
  }
  if (!publicKeyPem.endsWith('-----END PUBLIC KEY-----')) {
    throw new Error('Invalid public key PEM format - missing footer');
  }

  const publicKey = createPublicKey(publicKeyPem);
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;

  return {
    keys: [
      {
        kty: jwk.kty,
        use: 'sig',
        kid: FIREBASE_KID,
        alg: 'RS256',
        n: jwk.n,
        e: jwk.e,
      },
    ],
  };
}
