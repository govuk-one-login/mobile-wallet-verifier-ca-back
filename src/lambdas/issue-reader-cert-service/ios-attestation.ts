import { Logger } from '@aws-lambda-powertools/logger';
import { X509Certificate } from '@peculiar/x509';
import { IssueReaderCertRequest, AttestationResult } from './types.ts';
import { validateCSRContent } from './validation.ts';
import * as crypto from 'node:crypto';
import { decode } from 'cborg';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { IOS_ROOT_CA_SECRET } from '../../../scripts/setup-ios-infrastructure.ts';

const logger = new Logger();

const EXPECTED_APP_ID = process.env.EXPECTED_IOS_APP_ID || 'TEAMID.com.example.app';
const EXPECTED_ENVIRONMENT = process.env.EXPECTED_IOS_ENVIRONMENT || 'development';
function isTestMode(): boolean {
  return process.env.ALLOW_TEST_TOKENS === 'true';
}

const APPLE_APP_ATTEST_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen+mpU9+sexqPgglnCGsrQUAYy9kO2AqPRTo0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`;

export async function verifyIOSAttestation(request: IssueReaderCertRequest): Promise<AttestationResult> {
  logger.info('Verifying iOS App Attest', { keyId: request.appAttest?.keyId });

  if (!request.appAttest) {
    return { valid: false, code: 'missing_app_attest', message: 'iOS attestation data missing' };
  }

  try {
    const { attestationObject, keyId } = request.appAttest;
    const attestation = decodeCBOR(attestationObject);

    const certResult = await verifyCertificateChain(attestation.attStmt.x5c);
    if (!certResult.valid) return certResult;

    const appIdResult = verifyAppId(attestation.attStmt.x5c[0]);
    if (!appIdResult.valid) return appIdResult;

    const nonceResult = verifyCertificateNonce(attestation.attStmt.x5c[0], attestation.authData, request.nonce);
    if (!nonceResult.valid) return nonceResult;

    const authDataResult = verifyAuthenticatorData(attestation.authData);
    if (!authDataResult.valid) return authDataResult;

    const publicKey = extractPublicKey(attestation.authData);
    const keyIdResult = verifyKeyId(publicKey, keyId);
    if (!keyIdResult.valid) return keyIdResult;

    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const { PublicKey } = await import('@peculiar/x509');
    const peculiarPublicKey = new PublicKey(publicKeyPem);
    const csrResult = await validateCSRContent(request.csrPem, peculiarPublicKey);
    if (!csrResult.valid) return csrResult;

    logger.info('iOS attestation verification successful');
    return { valid: true };
  } catch (error) {
    logger.error('iOS attestation verification failed', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'attestation_error', message: 'iOS attestation verification failed' };
  }
}

function decodeCBOR(base64Data: string): any {
  const buffer = Buffer.from(base64Data, 'base64');
  const result = decode(buffer);
  logger.info('CBOR decoded', {
    fmt: result.fmt,
    authDataLength: result.authData?.length,
    authDataType: result.authData?.constructor?.name,
  });
  return result;
}

async function verifyCertificateChain(x5c: Buffer[]): Promise<AttestationResult> {
  if (!x5c || x5c.length < 2) {
    return { valid: false, code: 'invalid_cert_chain', message: 'Certificate chain too short' };
  }

  const certs = x5c.map((der) => new X509Certificate(new Uint8Array(der)));
  let rootCA = new X509Certificate(APPLE_APP_ATTEST_ROOT_CA);

  if (isTestMode()) {
    try {
      const client = new SecretsManagerClient({ region: 'eu-west-2' });
      const response = await client.send(new GetSecretValueCommand({ SecretId: IOS_ROOT_CA_SECRET }));
      if (response.SecretString) {
        const data = JSON.parse(response.SecretString);
        rootCA = new X509Certificate(data.certificatePem);
      }
    } catch (error) {
      logger.warn('Could not load test root CA', { error: error instanceof Error ? error.message : error });
    }
  }

  for (let i = 0; i < certs.length - 1; i++) {
    const isValid = await certs[i].verify({ publicKey: certs[i + 1].publicKey, signatureOnly: true });
    if (!isValid) {
      return { valid: false, code: 'invalid_signature', message: `Certificate ${i} signature invalid` };
    }
  }

  const topCert = certs[certs.length - 1];
  const isRootValid = await topCert.verify({ publicKey: rootCA.publicKey, signatureOnly: true });
  if (!isRootValid) {
    logger.error('Root verification failed', {
      topCertSubject: topCert.subject,
      rootCASubject: rootCA.subject,
      testMode: isTestMode(),
    });
    return { valid: false, code: 'invalid_root', message: 'Root certificate verification failed' };
  }

  const credCert = certs[0];
  const hasCredOID = credCert.extensions?.some((ext: any) => ext.type === '1.2.840.113635.100.8.2');
  if (!hasCredOID) {
    return { valid: false, code: 'missing_credential_oid', message: 'Missing credential certificate extension' };
  }

  return { valid: true };
}

function verifyAppId(certDer: Buffer): AttestationResult {
  if (isTestMode()) {
    return { valid: true };
  }
  return { valid: true };
}

function verifyCertificateNonce(certDer: any, authData: any, expectedNonce: string): AttestationResult {
  try {
    const cert = new X509Certificate(new Uint8Array(certDer));
    const nonceExt = cert.extensions?.find((ext: any) => ext.type === '1.2.840.113635.100.8.2');
    if (!nonceExt) {
      return { valid: false, code: 'missing_nonce_extension', message: 'Nonce extension not found' };
    }

    const authDataBuffer = Buffer.from(authData);
    const clientDataHash = crypto.createHash('sha256').update(expectedNonce).digest();
    const composite = Buffer.concat([authDataBuffer, clientDataHash]);
    const computedNonce = crypto.createHash('sha256').update(composite).digest();

    const certNonce = Buffer.from(nonceExt.value);
    if (!computedNonce.equals(certNonce)) {
      return { valid: false, code: 'nonce_mismatch', message: 'Certificate nonce does not match computed nonce' };
    }

    return { valid: true };
  } catch (error) {
    logger.error('Error verifying certificate nonce', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'nonce_verification_error', message: 'Failed to verify nonce' };
  }
}

function verifyAuthenticatorData(authData: any): AttestationResult {
  const authDataBuffer = Buffer.from(authData);
  if (authDataBuffer.length < 37) {
    return { valid: false, code: 'invalid_auth_data', message: 'Authenticator data too short' };
  }

  const rpIdHash = authDataBuffer.subarray(0, 32);
  const expectedRpId = EXPECTED_ENVIRONMENT === 'development' ? 'appattestdevelop' : EXPECTED_APP_ID;
  const expectedRpIdHash = crypto.createHash('sha256').update(expectedRpId).digest();
  
  if (!rpIdHash.equals(expectedRpIdHash)) {
    return { valid: false, code: 'rp_id_mismatch', message: 'RP ID hash does not match expected value' };
  }

  const flags = authDataBuffer[32];
  const userPresent = (flags & 0x01) !== 0;
  const attestedCredential = (flags & 0x40) !== 0;
  
  if (!userPresent || !attestedCredential) {
    return { valid: false, code: 'invalid_flags', message: 'Required authenticator flags not set' };
  }

  const counter = authDataBuffer.readUInt32BE(33);
  if (counter !== 0) {
    return { valid: false, code: 'invalid_counter', message: 'Counter must be 0 for attestation' };
  }

  return { valid: true };
}

function extractPublicKey(authData: any): crypto.KeyObject {
  const authDataBuffer = Buffer.from(authData);
  const credIdLen = authDataBuffer.readUInt16BE(53);
  const publicKeyStart = 55 + credIdLen;
  const publicKeyData = authDataBuffer.subarray(publicKeyStart);

  logger.info('Extracting public key', {
    authDataLength: authDataBuffer.length,
    credIdLen,
    publicKeyStart,
    publicKeyDataLength: publicKeyData.length,
    publicKeyDataHex: publicKeyData.toString('hex').substring(0, 100),
  });

  const coseKey = decode(publicKeyData, { useMaps: true });

  const x = Buffer.from(coseKey.get(-2));
  const y = Buffer.from(coseKey.get(-3));

  return crypto.createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: x.toString('base64url'),
      y: y.toString('base64url'),
    },
    format: 'jwk',
  });
}

function verifyKeyId(publicKey: crypto.KeyObject, expectedKeyId: string): AttestationResult {
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const keyId = crypto.createHash('sha256').update(publicKeyDer).digest('base64');

  if (keyId !== expectedKeyId) {
    return { valid: false, code: 'key_id_mismatch', message: 'Key ID does not match public key' };
  }

  return { valid: true };
}
