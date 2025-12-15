import { Logger } from '@aws-lambda-powertools/logger';
import { X509Certificate } from '@peculiar/x509';
import { IssueReaderCertRequest, AttestationResult } from './types.ts';
import { validateCSRContent } from './validation.ts';
import * as crypto from 'node:crypto';
import { decode } from 'cborg';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { IOS_ROOT_CA_SECRET } from '../../../scripts/setup-ios-infrastructure.ts';
import {
  APPLE_OIDS,
  AUTH_DATA_OFFSETS,
  AUTH_FLAGS,
  COSE_KEY_PARAMS,
  COSE_ALGORITHMS,
  COSE_CURVES,
  APPLE_VALUES,
  HASH_ALGORITHMS,
} from './ios-attestation-constants.js';

const logger = new Logger();

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

/**
 * Verifies iOS App Attest attestation following Apple's specification
 * Validates certificate chain, nonce, authenticator data, and CSR key matching
 */
export async function verifyIOSAttestation(request: IssueReaderCertRequest): Promise<AttestationResult> {
  logger.info('Verifying iOS App Attest', { keyId: request.appAttest?.keyId });

  if (!request.appAttest) {
    return { valid: false, code: 'missing_app_attest', message: 'iOS attestation data missing' };
  }

  try {
    const { attestationObject, keyId } = request.appAttest;
    const attestation = decodeCBOR(attestationObject);

    //https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-attestation
    if (attestation.fmt !== APPLE_VALUES.ATTESTATION_FORMAT) {
      return { valid: false, code: 'invalid_format', message: 'Invalid attestation format' };
    }

    const validations = [
      () => verifyCertificateChain(attestation.attStmt.x5c),
      () => verifyCertificateNonce(attestation.attStmt.x5c[0], attestation.authData, request.nonce),
      () => verifyCertificatePublicKey(attestation.attStmt.x5c[0], attestation.authData),
      () => verifyAuthenticatorData(attestation.authData),
      () => verifyCSRMatchesAttestedKey(attestation.authData, keyId, request.csrPem),
    ];

    for (const validation of validations) {
      const result = await validation();
      if (!result.valid) return result;
    }

    logger.info('iOS attestation verification successful');
    return { valid: true };
  } catch (error) {
    logger.error('iOS attestation verification failed', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'attestation_error', message: 'iOS attestation verification failed' };
  }
}

/**
 * Decodes base64-encoded CBOR attestation object
 */
function decodeCBOR(base64Data: string): any {
  try {
    const buffer = Buffer.from(base64Data, 'base64');
    const result = decode(buffer);
    logger.info('CBOR decoded', {
      fmt: result.fmt,
      authDataLength: result.authData?.length,
      authDataType: result.authData?.constructor?.name,
    });
    return result;
  } catch (error) {
    logger.error('CBOR decode failed', { error: error instanceof Error ? error.message : error });
    throw new Error('Invalid attestation object format');
  }
}

/**
 * Verifies X.509 certificate chain against Apple App Attest root CA
 * Checks validity periods and signature chain up to root
 */
async function verifyCertificateChain(x5c: Buffer[]): Promise<AttestationResult> {
  if (!x5c || x5c.length < APPLE_VALUES.MIN_CERT_CHAIN_LENGTH) {
    return { valid: false, code: 'invalid_cert_chain', message: 'Certificate chain too short' };
  }

  const certs = x5c.map((der) => new X509Certificate(new Uint8Array(der)));
  
  const now = new Date();
  for (const cert of certs) {
    if (cert.notBefore > now || cert.notAfter < now) {
      return { valid: false, code: 'cert_expired', message: 'Certificate not valid for current time' };
    }
  }

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

  return { valid: true };
}

/**
 * Verifies nonce in certificate matches computed value from authData + challenge
 * Implements Apple's nonce verification: SHA256(authData || SHA256(nonce))
 */
function verifyCertificateNonce(certDer: any, authData: any, expectedNonce: string): AttestationResult {
  try {
    const cert = new X509Certificate(new Uint8Array(certDer));
    
    const nonceExt = cert.extensions?.find((ext: any) => ext.type === APPLE_OIDS.NONCE_EXTENSION);
    if (!nonceExt) {
      return { valid: false, code: 'missing_nonce_extension', message: 'Nonce extension not found' };
    }

    // Apple's nonce computation: SHA256(authData || SHA256(challenge))
    const authDataBuffer = Buffer.from(authData);
    const clientDataHash = crypto.createHash(HASH_ALGORITHMS.SHA256).update(expectedNonce).digest();
    const composite = Buffer.concat([authDataBuffer, clientDataHash]);
    const computedNonce = crypto.createHash(HASH_ALGORITHMS.SHA256).update(composite).digest();

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

/**
 * Verifies WebAuthn authenticator data structure and Apple-specific values
 * Checks RP ID hash, AAGUID, flags, and counter
 */
function verifyAuthenticatorData(authData: any): AttestationResult {
  const authDataBuffer = Buffer.from(authData);
  if (authDataBuffer.length < APPLE_VALUES.MIN_AUTH_DATA_LENGTH) {
    return { valid: false, code: 'invalid_auth_data', message: 'Authenticator data too short' };
  }

  const rpIdHash = authDataBuffer.subarray(AUTH_DATA_OFFSETS.RP_ID_HASH_START, AUTH_DATA_OFFSETS.RP_ID_HASH_END);
  const expectedRpId = APPLE_VALUES.AAGUID_DEVELOPMENT;
  const expectedRpIdHash = crypto.createHash(HASH_ALGORITHMS.SHA256).update(expectedRpId).digest();
  
  if (!rpIdHash.equals(expectedRpIdHash)) {
    return { valid: false, code: 'rp_id_mismatch', message: 'RP ID hash does not match expected value' };
  }

  const aaguid = authDataBuffer.subarray(AUTH_DATA_OFFSETS.AAGUID_START, AUTH_DATA_OFFSETS.AAGUID_END);
  const expectedAAGUID = Buffer.from(APPLE_VALUES.AAGUID_DEVELOPMENT, 'utf8');
  if (!aaguid.equals(expectedAAGUID)) {
    return { valid: false, code: 'invalid_aaguid', message: 'AAGUID does not match Apple App Attest' };
  }

  //https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
  const flags = authDataBuffer[AUTH_DATA_OFFSETS.FLAGS];
  const userPresent = (flags & AUTH_FLAGS.USER_PRESENT) !== 0;
  const attestedCredential = (flags & AUTH_FLAGS.ATTESTED_CREDENTIAL) !== 0;
  
  if (!userPresent || !attestedCredential) {
    return { valid: false, code: 'invalid_flags', message: 'Required authenticator flags not set' };
  }

  const counter = authDataBuffer.readUInt32BE(AUTH_DATA_OFFSETS.COUNTER_START);
  if (counter !== APPLE_VALUES.EXPECTED_COUNTER) {
    return { valid: false, code: 'invalid_counter', message: 'Counter must be 0 for attestation' };
  }

  return { valid: true };
}

/**
 * Extracts ECDSA P-256 public key from COSE-encoded credential data
 * Parses CBOR-encoded public key and converts to Node.js KeyObject
 */
function extractPublicKey(authData: any): crypto.KeyObject {
  const authDataBuffer = Buffer.from(authData);
  const credIdLen = authDataBuffer.readUInt16BE(AUTH_DATA_OFFSETS.CRED_ID_LEN_START);
  const publicKeyStart = AUTH_DATA_OFFSETS.CRED_DATA_START + credIdLen;
  const publicKeyData = authDataBuffer.subarray(publicKeyStart);

  const coseKey = decode(publicKeyData, { useMaps: true });

  const x = Buffer.from(coseKey.get(COSE_KEY_PARAMS.X));
  const y = Buffer.from(coseKey.get(COSE_KEY_PARAMS.Y));

  //Converts to JWK format for Node.js crypto compatibility
  //Creates KeyObject for standard crypto operations
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

/**
 * Verifies key ID matches SHA256 hash of public key DER encoding
 */
function verifyKeyId(publicKey: crypto.KeyObject, expectedKeyId: string): AttestationResult {
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const keyId = crypto.createHash(HASH_ALGORITHMS.SHA256).update(publicKeyDer).digest('base64');

  if (keyId !== expectedKeyId) {
    return { valid: false, code: 'key_id_mismatch', message: 'Key ID does not match public key' };
  }

  return { valid: true };
}

/**
 * Extracts credential ID from authenticator data
 */
function extractCredentialId(authData: any): Buffer {
  const authDataBuffer = Buffer.from(authData);
  const credIdLen = authDataBuffer.readUInt16BE(AUTH_DATA_OFFSETS.CRED_ID_LEN_START);
  return authDataBuffer.subarray(AUTH_DATA_OFFSETS.CRED_DATA_START, AUTH_DATA_OFFSETS.CRED_DATA_START + credIdLen);
}

/**
 * Verifies credential ID matches the provided key identifier
 */
function verifyCredentialId(authData: any, expectedKeyId: string): AttestationResult {
  const credentialId = extractCredentialId(authData);
  const credentialIdBase64 = credentialId.toString('base64');
  
  if (credentialIdBase64 !== expectedKeyId) {
    return { valid: false, code: 'credential_id_mismatch', message: 'Credential ID does not match key identifier' };
  }
  
  return { valid: true };
}

/**
 * Verifies public key algorithm is ES256 (ECDSA P-256)
 */
function verifyPublicKeyAlgorithm(authData: any): AttestationResult {
  const authDataBuffer = Buffer.from(authData);
  const credIdLen = authDataBuffer.readUInt16BE(AUTH_DATA_OFFSETS.CRED_ID_LEN_START);
  const publicKeyStart = AUTH_DATA_OFFSETS.CRED_DATA_START + credIdLen;
  const publicKeyData = authDataBuffer.subarray(publicKeyStart);
  
  const coseKey = decode(publicKeyData, { useMaps: true });
  const alg = coseKey.get(COSE_KEY_PARAMS.ALG);
  const crv = coseKey.get(COSE_KEY_PARAMS.CRV);
  
  if (alg !== COSE_ALGORITHMS.ES256) {
    return { valid: false, code: 'invalid_algorithm', message: 'Public key algorithm must be ES256' };
  }
  
  if (crv !== COSE_CURVES.P256) {
    return { valid: false, code: 'invalid_curve', message: 'Public key curve must be P-256' };
  }
  
  return { valid: true };
}

/**
 * Verifies certificate public key matches authenticator data public key
 */
async function verifyCertificatePublicKey(certDer: any, authData: any): Promise<AttestationResult> {
  const cert = new X509Certificate(new Uint8Array(certDer));
  const authDataPublicKey = extractPublicKey(authData);
  
  const certPublicKeyDer = Buffer.from(cert.publicKey.rawData);
  const authDataPublicKeyDer = authDataPublicKey.export({ type: 'spki', format: 'der' }) as Buffer;

  
  if (!certPublicKeyDer.equals(authDataPublicKeyDer)) {
    return { valid: false, code: 'public_key_mismatch', message: 'Certificate public key does not match authenticator data public key' };
  }
  
  return { valid: true };
};

/**
 * Verifies CSR public key matches the attested key from authenticator data
 * Ensures the certificate request uses the same key that was attested
 */
async function verifyCSRMatchesAttestedKey(authData: any, keyId: string, csrPem: string): Promise<AttestationResult> {
  const credIdResult = verifyCredentialId(authData, keyId);
  if (!credIdResult.valid) return credIdResult;

  const algResult = verifyPublicKeyAlgorithm(authData);
  if (!algResult.valid) return algResult;

  const publicKey = extractPublicKey(authData);
  const keyIdResult = verifyKeyId(publicKey, keyId);
  if (!keyIdResult.valid) return keyIdResult;

  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const { PublicKey } = await import('@peculiar/x509');
  const peculiarPublicKey = new PublicKey(publicKeyPem);
  return validateCSRContent(csrPem, peculiarPublicKey);
}
