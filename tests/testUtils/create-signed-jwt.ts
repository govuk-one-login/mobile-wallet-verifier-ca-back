import {
  CompactSign,
  exportJWK,
  generateKeyPair,
  JWK,
  JWTHeaderParameters,
  SignJWT,
} from 'jose';
import { randomUUID } from 'crypto';

export async function createSignedJwt(
  privateKey: CryptoKey,
  options: {
    includeKid?: boolean;
    issuer?: string;
    audience?: string;
    subject?: string;
    jti?: string;
    alg?: string;
    kid?: string;
    includeExp?: boolean;
    expOffsetSeconds?: number;
  } = {},
): Promise<string> {
  const nowInSeconds = Math.floor(Date.now() / 1000);
  const protectedHeader: JWTHeaderParameters = {
    alg: options.alg ?? 'RS256',
    typ: 'JWT',
  };
  if (options.includeKid !== false) {
    protectedHeader.kid = options.kid ?? 'mockKeyId';
  }

  let signedToken = new SignJWT({})
    .setProtectedHeader(protectedHeader)
    .setIssuer(options.issuer ?? 'mockIssuer')
    .setAudience(options.audience ?? 'mockAudience')
    .setSubject(options.subject ?? 'mockSubject')
    .setJti(options.jti ?? randomUUID())
    .setNotBefore(nowInSeconds - 5);

  if (options.includeExp !== false) {
    signedToken = signedToken.setExpirationTime(
      nowInSeconds + (options.expOffsetSeconds ?? 120),
    );
  }

  return signedToken.sign(privateKey);
}

export async function createSignedNonJsonJwt(
  privateKey: CryptoKey,
): Promise<string> {
  return new CompactSign(new TextEncoder().encode('not-json'))
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'JWT',
      kid: 'mockKeyId',
    })
    .sign(privateKey);
}

export async function createMalformedJws(
  privateKey: CryptoKey,
): Promise<string> {
  const jwt = await createSignedJwt(privateKey);
  const [header, payload] = jwt.split('.');
  return `${header}.${payload}.not-base64!`;
}

export async function createJwtWithInvalidProtectedHeader(
  privateKey: CryptoKey,
): Promise<string> {
  const jwt = await createSignedJwt(privateKey);
  const [, payload, signature] = jwt.split('.');
  return `not-base64!.${payload}.${signature}`;
}

export async function createKeyPair(): Promise<{
  privateKey: CryptoKey;
  publicJwk: JWK;
}> {
  const generatedKeyPair = await generateKeyPair('RS256');
  const privateKey = generatedKeyPair.privateKey;
  const publicJwk = await exportJWK(generatedKeyPair.publicKey);
  publicJwk.kid = 'mockKeyId';
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';

  return {
    privateKey,
    publicJwk,
  };
}
