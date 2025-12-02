import { Logger } from '@aws-lambda-powertools/logger';
import { X509Certificate, Pkcs10CertificateRequest, BasicConstraintsExtension, X509ChainBuilder } from '@peculiar/x509';
import { KeyDescription, SecurityLevel } from '@peculiar/asn1-android';
import { AsnConvert } from '@peculiar/asn1-schema';
import * as jose from 'jose';
import { IssueReaderCertRequest, AttestationResult } from './types.ts';

// Richa TO CHECK - should be store these google root certs in secrets manager or call via api/cache etc?
// Google Hardware Attestation Root certificates (from Android documentation)
const TRUSTED_ROOT_CERTIFICATES = [
  // Production Google roots from https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
  `-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----`,
  `-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----`
];

const CRL_URL = 'https://android.googleapis.com/attestation/status';

const logger = new Logger();

/**
 * Verifies Android attestation including Play Integrity and key attestation chain
 * @param request - The certificate request containing Android attestation data
 * @returns Attestation verification result
 */
export async function verifyAndroidAttestation(request: IssueReaderCertRequest): Promise<AttestationResult> {
  logger.info('Verifying Android attestation', { chainLength: request.keyAttestationChain?.length });

  try {
    const validations = [
      () => verifyPlayIntegrityToken(request.playIntegrityToken!, request.nonce), // Verify Play Integrity token signature and payload
      () => validateCertificates(request.keyAttestationChain!), // Validate certificate chain properties
      () => verifyAttestationChallenge(request.keyAttestationChain!, request.nonce), // Verify attestation challenge matches nonce
      () => comparePublicKeys(request.csrPem, request.keyAttestationChain!) // Ensure CSR and attestation use same key
    ];

    for (const validation of validations) {
      const result = await validation();
      if (!result.valid) return result;
    }

    logger.info('Android attestation verification successful');
    return { valid: true };

  } catch (error) {
    logger.error('Error during Android attestation verification', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'attestation_error', message: 'Internal error during attestation verification' };
  }
}

/**
 * Verifies Play Integrity token (signature, nonce, and payload validation)
 */
async function verifyPlayIntegrityToken(token: string, expectedNonce: string): Promise<AttestationResult> {
  try {
    // Skip signature verification in development mode
    if (process.env.ALLOW_TEST_TOKENS === 'true') {
      logger.info('Skipping Google JWKS verification in development mode');
    } else {
      // Verify signature using Google's JWKS
      const header = jose.decodeProtectedHeader(token);
      if (!header.kid) {
        return { valid: false, code: 'invalid_play_integrity', message: 'JWT header missing kid (key ID)' };
      }
      
      const JWKS = jose.createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'), {
        cooldownDuration: 30000,
        cacheMaxAge: 600000
      });
      
      await jose.jwtVerify(token, JWKS, {
        issuer: 'https://playintegrity.googleapis.com/',
        algorithms: ['RS256']
      });
    }

    // Decode and validate payload
    const payload = jose.decodeJwt(token);
    const { requestDetails, appIntegrity, deviceIntegrity, accountDetails } = payload as any;
    
    // Verify nonce
    if (requestDetails?.nonce !== expectedNonce) {
      return { valid: false, code: 'nonce_mismatch', message: 'Play Integrity nonce does not match request nonce' };
    }
    
    //Richa - TO CHECK is this check needed, in sequence diag?
    // Validate app identity
    const expectedPackageName = process.env.EXPECTED_PACKAGE_NAME || 'org.multipaz.identityreader';
    if (appIntegrity?.packageName !== expectedPackageName) {
      return { valid: false, code: 'invalid_package', message: 'Package name mismatch' };
    }
    
    if (appIntegrity?.appRecognitionVerdict !== 'PLAY_RECOGNIZED') {
      return { valid: false, code: 'app_not_recognized', message: 'App not recognized by Play Store' };
    }
    

    //Richa - TO CHECK is this check needed, not in sequence diag?
    // Validate device integrity
    const deviceVerdicts = deviceIntegrity?.deviceRecognitionVerdict || [];
    const hasValidDevice = deviceVerdicts.includes('MEETS_DEVICE_INTEGRITY') || 
                          deviceVerdicts.includes('MEETS_BASIC_INTEGRITY');
    if (!hasValidDevice) {
      return { valid: false, code: 'device_integrity_failed', message: 'Device integrity check failed' };
    }
    
    //Richa - TO CHECK is this check needed, not in sequence diag?
    // Validate app licensing
    if (accountDetails?.appLicensingVerdict === 'UNEVALUATED') {
      logger.warn('App licensing could not be evaluated');
    } else if (accountDetails?.appLicensingVerdict !== 'LICENSED') {
      return { valid: false, code: 'app_not_licensed', message: 'App is not properly licensed' };
    }
    
    return { valid: true };
  } catch (error) {
    logger.error('Error verifying Play Integrity token', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'invalid_play_integrity', message: 'Play Integrity token verification failed' };
  }
}

/**
 * Validates all certificate properties (Android chains are already properly ordered)
 */
async function validateCertificates(x5c: string[]): Promise<AttestationResult> {
  try {
    const certificates = parseCertificates(x5c);
    if (!certificates.valid) return certificates;
    
    // Richa TO CHECK - most of these checks on cert chain are not in sequence diag but were present in spike validation?
    const validations = [
      () => validateBasicConstraints(certificates.certificates!),
      () => validateSignatures(certificates.certificates!),
      () => validateTrustedRoot(certificates.certificates![certificates.certificates!.length - 1]),
      () => checkCertificateRevocation(certificates.certificates!),
      () => validateCertificateValidity(certificates.certificates!),
      () => validateAttestationExtensionCount(certificates.certificates!)
    ];
    
    for (const validation of validations) {
      const result = await validation();
      if (!result.valid) return result;
    }
    
    return { valid: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (error instanceof TypeError || errorMessage.includes('verify')) {
      return { valid: false, message: `Certificate validation error: ${errorMessage}` };
    }
    logger.warn('Non-critical validation service error', { error: errorMessage });
    return { valid: true };
  }
}

function parseCertificates(x5c: string[]): AttestationResult & { certificates?: X509Certificate[] } {
  if (!x5c || x5c.length === 0) {
    return { valid: false, message: 'Certificate chain is empty' };
  }
  
  const certificates = x5c.map(certB64 => new X509Certificate(Buffer.from(certB64, 'base64')));
  if (certificates.length < 2) {
    return { valid: false, message: `Certificate chain too short (${certificates.length} certificates, minimum 2 required)` };
  }
  
  return { valid: true, certificates };
}

function validateBasicConstraints(certificates: X509Certificate[]): AttestationResult {
  for (let i = 0; i < certificates.length; i++) {
    const cert = certificates[i];
    const basicConstraintsExts = cert.extensions?.filter(ext => (ext as any).type === '2.5.29.19') || [];
    
    if (basicConstraintsExts.length > 1) {
      return { valid: false, message: `Certificate ${i} has multiple Basic Constraints extensions` };
    }
    
    if (i === 0) {
      // Leaf certificate should NOT be a CA
      if (basicConstraintsExts.length > 0) {
        const basicConstraints = new BasicConstraintsExtension(basicConstraintsExts[0].rawData);
        if (basicConstraints.ca) {
          return { valid: false, message: 'Leaf certificate incorrectly marked as CA' };
        }
      }
    } else {
      // Intermediate/root certificates should have basic constraints and be CAs
      if (basicConstraintsExts.length === 0) {
        return { valid: false, message: `Certificate ${i} missing Basic Constraints extension` };
      }
      const basicConstraints = new BasicConstraintsExtension(basicConstraintsExts[0].rawData);
      if (!basicConstraints.ca) {
        return { valid: false, message: `Certificate ${i} not marked as CA` };
      }
    }
  }
  return { valid: true };
}

async function validateSignatures(certificates: X509Certificate[]): Promise<AttestationResult> {
  for (let i = 0; i < certificates.length; i++) {
    const cert = certificates[i];
    const signerKey = i < certificates.length - 1 ? certificates[i + 1].publicKey : cert.publicKey;
    
    const isValid = await cert.verify({ publicKey: signerKey, signatureOnly: true });
    if (!isValid) {
      return { valid: false, message: `Certificate ${i} signature verification failed` };
    }
  }
  return { valid: true };
}

async function checkCertificateRevocation(certificates: X509Certificate[]): Promise<AttestationResult> {
  const response = await fetch(CRL_URL, { 
    method: 'GET',
    headers: { 'Accept': 'application/json' },
    signal: AbortSignal.timeout(5000)
  });
  
  if (!response.ok) {
    const errorMsg = `CRL service unavailable (HTTP ${response.status})`;
    logger.error(errorMsg);
    
    if (process.env.NODE_ENV === 'production' && process.env.STRICT_CRL_CHECK === 'true') {
      return { valid: false, code: 'crl_unavailable', message: errorMsg };
    }
    
    logger.warn('Continuing validation without CRL check in non-strict mode');
    return { valid: true };
  }
  
  const crlData = await response.json();
  const entries = crlData.entries || {};
  
  for (const cert of certificates) {
    const entry = entries[cert.serialNumber];
    if (entry?.status === 'REVOKED') {
      return { valid: false, code: 'certificate_revoked', message: `Certificate ${cert.serialNumber} is revoked: ${entry.reason || 'Unknown reason'}` };
    }
  }
  
  return { valid: true };
}

function validateCertificateValidity(certificates: X509Certificate[]): AttestationResult {
  const now = new Date();
  
  for (let i = 0; i < certificates.length; i++) {
    const cert = certificates[i];
    if (now < cert.notBefore || now > cert.notAfter) {
      const certType = i === 0 ? 'Leaf' : i === certificates.length - 1 ? 'Root' : 'Intermediate';
      return { valid: false, message: `${certType} certificate not valid at current time (valid from ${cert.notBefore} to ${cert.notAfter})` };
    }
  }
  
  return { valid: true };
}

function validateAttestationExtensionCount(certificates: X509Certificate[]): AttestationResult {
  const attestationExtCount = certificates.reduce((count, cert) => {
    return count + (cert.extensions?.filter(ext => (ext as any).type === '1.3.6.1.4.1.11129.2.1.17').length || 0);
  }, 0);
  
  if (attestationExtCount !== 1) {
    return { valid: false, message: `Expected exactly 1 attestation extension, found ${attestationExtCount}` };
  }
  
  return { valid: true };
}


/**
 * Verifies attestation challenge and validates leaf certificate
 */
async function verifyAttestationChallenge(x5c: string[], expectedNonce: string): Promise<AttestationResult> {
  try {
    const leafCert = new X509Certificate(Buffer.from(x5c[0], 'base64'));
    
    // Validate certificate validity period
    const now = new Date();
    if (now < leafCert.notBefore || now > leafCert.notAfter) {
      return { valid: false, message: `Certificate not valid at current time (valid from ${leafCert.notBefore} to ${leafCert.notAfter})` };
    }
    
    // Find and validate attestation extension
    const attestationOid = '1.3.6.1.4.1.11129.2.1.17';
    const extension = leafCert.extensions?.find((ext: any) => ext.type === attestationOid);
    if (!extension) {
      return { valid: false, code: 'missing_attestation_extension', message: 'Missing attestation extension' };
    }
    
    //Richa - TO CHECK if have any view on adding checks for keyAlgo/curve?
    // Validate key algorithm
    const keyAlgorithm = leafCert.publicKey.algorithm.name;
    if (keyAlgorithm === 'ECDSA') {
      const namedCurve = (leafCert.publicKey.algorithm as any).namedCurve;
      const validCurves = ['P-256', 'P-384', 'P-521'];
      if (!validCurves.includes(namedCurve)) {
        return { valid: false, message: `Invalid ECDSA curve: ${namedCurve} (expected P-256, P-384, or P-521 per Android CDD)` };
      }
    } else if (keyAlgorithm === 'RSASSA-PKCS1-v1_5') {
      const modulusLength = (leafCert.publicKey.algorithm as any).modulusLength;
      const validSizes = [2048, 3072, 4096];
      if (!validSizes.includes(modulusLength)) {
        return { valid: false, message: `Invalid RSA key size: ${modulusLength} (expected 2048, 3072, or 4096 bits per Android CDD)` };
      }
    } else {
      return { valid: false, message: `Unsupported key algorithm: ${keyAlgorithm} (expected ECDSA or RSA per Android Key Attestation spec)` };
    }
    
    // Parse and verify attestation extension
    const keyDescription = AsnConvert.parse(extension.value, KeyDescription);
    if (!keyDescription.attestationChallenge) {
      return { valid: false, code: 'missing_attested_challenge', message: 'Failed to extract attested challenge' };
    }
    
    const challengeBytes = new Uint8Array(keyDescription.attestationChallenge.buffer);
    const attestedChallenge = Buffer.from(challengeBytes).toString('utf8');
    console.log('Attested Challenge:', attestedChallenge);
    if (attestedChallenge !== expectedNonce) {
      return { valid: false, code: 'challenge_mismatch', message: 'Attested challenge does not match nonce' };
    }
    
    // Verify security levels
    const validSecurityLevels = [SecurityLevel.trustedEnvironment, SecurityLevel.strongBox];
    const validLevels = [keyDescription.attestationSecurityLevel, keyDescription.keymasterSecurityLevel]
      .every(level => validSecurityLevels.includes(level));
    if (!validLevels) {
      return { valid: false, code: 'invalid_security_level', message: 'Attestation security level verification failed' };
    }
    
    return { valid: true };
  } catch (error) {
    logger.error('Error verifying attestation challenge', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'attestation_extension_error', message: 'Failed to verify attestation challenge' };
  }
}


/**
 * Validates root certificate against trusted Google roots
 */
function validateTrustedRoot(rootCert: X509Certificate): AttestationResult {
  const rootSubject = rootCert.subject;
  const isGoogleRoot = rootSubject.includes('Google');
  const isTestRoot = rootSubject.includes('Test');
  
  if (!isGoogleRoot && !isTestRoot) {
    return { valid: false, message: `Root certificate not from Google or test CA (subject: ${rootSubject})` };
  }
  
  // For production, validate against known Google root public keys
  if (process.env.NODE_ENV === 'production' && !isTestRoot) {
    try {
      const rootPublicKeyRaw = Buffer.from(rootCert.publicKey.rawData);
      
      const isKnownRoot = TRUSTED_ROOT_CERTIFICATES.some(trustedRootPem => {
        try {
          const trustedRoot = new X509Certificate(trustedRootPem);
          const trustedPublicKeyRaw = Buffer.from(trustedRoot.publicKey.rawData);
          return rootPublicKeyRaw.equals(trustedPublicKeyRaw);
        } catch {
          return false;
        }
      });
      
      if (!isKnownRoot) {
        return { valid: false, message: 'Root certificate public key not in trusted Google roots' };
      }
    } catch (error) {
      logger.warn('Root public key validation failed', { error: error instanceof Error ? error.message : error });
    }
  }
  
  return { valid: true };
}

/**
 * Verifies that CSR public key matches the attested device public key
 * This ensures the CSR was generated with the same key that was attested
 */
async function comparePublicKeys(csrPem: string, attestationChain: string[]): Promise<AttestationResult> {
  try {
    // Extract public key from CSR (key requesting certificate)
    const csr = new Pkcs10CertificateRequest(csrPem);
    const csrSpkiThumbprint = await csr.publicKey.getThumbprint();

    // Extract public key from leaf attestation certificate (attested device key)
    const leafCert = new X509Certificate(Buffer.from(attestationChain[0], 'base64'));
    const attestedSpkiThumbprint = await leafCert.publicKey.getThumbprint();

    // Verify both keys are identical (same device key used for CSR and attestation)
    const keysMatch = Buffer.compare(Buffer.from(csrSpkiThumbprint), Buffer.from(attestedSpkiThumbprint)) === 0;
    
    if (!keysMatch) {
      return { 
        valid: false, 
        code: 'public_key_mismatch', 
        message: 'CSR public key does not match attested device public key - potential key substitution attack' 
      };
    }
    
    logger.info('Public key verification successful - CSR and attestation use same device key');
    return { valid: true };
  } catch (error) {
    logger.error('Error comparing public keys', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'public_key_mismatch', message: 'Failed to compare public keys' };
  }
}

