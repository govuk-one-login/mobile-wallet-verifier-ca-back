import { Logger } from '@aws-lambda-powertools/logger';
import { X509Certificate, Pkcs10CertificateRequest, BasicConstraintsExtension } from '@peculiar/x509';
import { KeyDescription, SecurityLevel } from '@peculiar/asn1-android';
import { AsnConvert } from '@peculiar/asn1-schema';
import * as jose from 'jose';
import { IssueReaderCertRequest, AttestationResult } from './types.ts';
import { validatePlayIntegritySignature, validatePlayIntegrityPayload } from './play-integrity-validator';

// Android attestation constants
//[C-1-5] MUST use verification algorithms as strong as current recommendations from NIST for hashing algorithms (SHA-256) and public key sizes (RSA-2048).
const ANDROID_ATTESTATION_CONFIG = {
  BASIC_CONSTRAINTS_OID: '2.5.29.19',
  ATTESTATION_EXTENSION_OID: '1.3.6.1.4.1.11129.2.1.17',
  VALID_ECDSA_CURVES: ['P-256', 'P-384', 'P-521'],
  VALID_RSA_SIZES: [2048, 3072, 4096],
  CRL_TIMEOUT: 5000,
  MIN_CERT_CHAIN_LENGTH: 2,
} as const;

// Richa TO CHECK - should be store these google root certs in secrets manager 
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

      if (!result.valid) {
        console.log(result.message);
        return result;
      }
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
    const signatureResult = await validatePlayIntegritySignature(token);
    if (!signatureResult.valid) return signatureResult;

    const payload = jose.decodeJwt(token);
    return validatePlayIntegrityPayload(payload, expectedNonce);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    // Handle specific Play Integrity error codes
    if (errorMessage.includes('INTEGRITY_TOKEN_PROVIDER_INVALID')) {
      return { valid: false, code: 'integrity_token_provider_invalid', message: 'Play Integrity API is not available on this device' };
    }
    
    logger.error('Error verifying Play Integrity token', { error: errorMessage });
    return { valid: false, code: 'invalid_play_integrity', message: 'Play Integrity token verification failed' };
  }
}

/**
 * Validates all certificate properties (All certs in Android chain are valid and poperly formed)
 */
async function validateCertificates(x5c: string[]): Promise<AttestationResult> {
  try {
    const certificates = parseCertificates(x5c);
    if (!certificates.valid) return certificates;
    
    // Richa TO CHECK - most of these checks on cert chain are not in sequence diag but were present in spike validation?
    const validations = [
      () => validateCertificateValidity(certificates.certificates!),
      () => validateSignatures(certificates.certificates!),
      () => validateCertificateExtensions(certificates.certificates!)
    ];
    
    for (const validation of validations) {
      const result = await validation();
      if (!result.valid) return result;
    }
    
    return { valid: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error('Certificate validation failed', { error: errorMessage });
    return { valid: false, message: `Certificate validation error: ${errorMessage}` };
  }
}

function parseCertificates(x5c: string[]): AttestationResult & { certificates?: X509Certificate[] } {
  // Richa to check later (redudant) 
  // if (!x5c || x5c.length < ANDROID_ATTESTATION_CONFIG.MIN_CERT_CHAIN_LENGTH) {
  //   return { valid: false, message: `Certificate chain too short (${x5c?.length || 0} certificates, minimum ${ANDROID_ATTESTATION_CONFIG.MIN_CERT_CHAIN_LENGTH} required)` };
  // }
  
  // Validate certificate format and parse
  const certificates: X509Certificate[] = [];
  for (let i = 0; i < x5c.length; i++) {
    try {
      const derBuffer = Buffer.from(x5c[i], 'base64');
      certificates.push(new X509Certificate(derBuffer));
    } catch (error) {
      return { valid: false, message: `Certificate ${i} is not valid X.509 ASN.1 format` };
    }
  }
  
  return { valid: true, certificates };
}

function validateCertificateExtensions(certificates: X509Certificate[]): AttestationResult {
  let attestationExtCount = 0;
  
  for (let i = 0; i < certificates.length; i++) {
    const cert = certificates[i];
    const basicConstraintsExts = cert.extensions?.filter(ext => (ext as any).type === ANDROID_ATTESTATION_CONFIG.BASIC_CONSTRAINTS_OID) || [];
    
    // Count attestation extensions across all certificates
    attestationExtCount += cert.extensions?.filter(ext => (ext as any).type === ANDROID_ATTESTATION_CONFIG.ATTESTATION_EXTENSION_OID).length || 0;
    
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
      // Intermediate certificates should have basic constraints and be CAs
      if (basicConstraintsExts.length === 0) {
        return { valid: false, message: `Certificate ${i} missing Basic Constraints extension` };
      }
      const basicConstraints = new BasicConstraintsExtension(basicConstraintsExts[0].rawData);
      if (!basicConstraints.ca) {
        return { valid: false, message: `Certificate ${i} not marked as CA` };
      }
    }
  }
  
  // Validate attestation extension count
  if (attestationExtCount !== 1) {
    return { valid: false, message: `Expected exactly 1 attestation extension, found ${attestationExtCount}` };
  }
  
  return { valid: true };
}

async function validateSignatures(certificates: X509Certificate[]): Promise<AttestationResult> {
  for (let i = 0; i < certificates.length - 1; i++) {
    const cert = certificates[i];
    const issuerCert = certificates[i + 1];
    
    // Validate DN chain
    if (cert.issuer !== issuerCert.subject) {
      return { valid: false, message: `Certificate ${i} issuer DN does not match issuing certificate ${i + 1} subject DN` };
    }
    
    // Verify signature using issuer's public key
    const isValid = await cert.verify({ publicKey: issuerCert.publicKey, signatureOnly: true });
    if (!isValid) {
      return { valid: false, message: `Certificate ${i} signature verification failed` };
    }
  }
  
  // Skip root validation in test mode
  if (process.env.ALLOW_TEST_TOKENS === 'true') {
    return { valid: true };
  }
  
  // Verify last certificate (intermediate) against trusted Google roots
  const topCert = certificates[certificates.length - 1];
  for (const trustedRootPem of TRUSTED_ROOT_CERTIFICATES) {
    try {
      const trustedRoot = new X509Certificate(trustedRootPem);
      if (trustedRoot.subject === topCert.issuer) {
        const isValid = await topCert.verify({ publicKey: trustedRoot.publicKey, signatureOnly: true });
        return isValid 
          ? { valid: true }
          : { valid: false, message: 'Certificate signature verification against trusted root failed' };
      }
    } catch {
      continue;
    }
  }
  
  return { valid: false, message: `Certificate chain does not link to trusted Google root. Expected issuer: ${topCert.issuer}` };
}

// Check against Android CRL list
async function checkCertificateRevocation(certificates: X509Certificate[]): Promise<AttestationResult> {
  // Skip CRL check in test mode
  if (process.env.ALLOW_TEST_TOKENS === 'true') {
    logger.info('Skipping CRL check in test mode');
    return { valid: true };
  }
  
  const response = await fetch(CRL_URL, { 
    method: 'GET',
    headers: { 'Accept': 'application/json' },
    signal: AbortSignal.timeout(ANDROID_ATTESTATION_CONFIG.CRL_TIMEOUT)
  });
  
  // Richa check if this is acceptable?
  if (!response.ok) {
    const errorMsg = `CRL service unavailable (HTTP ${response.status})`;
    logger.warn(errorMsg + ', continuing validation without CRL check');
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


/**
 * Verifies Key attestation challenge and validates leaf certificate
 */
async function verifyAttestationChallenge(x5c: string[], expectedNonce: string): Promise<AttestationResult> {
  try {
    const leafCert = new X509Certificate(Buffer.from(x5c[0], 'base64'));
        
    //Richa - TO CHECK if have any view on adding checks for keyAlgo/curve?
    // Reject RSA keyAlgo
    // Validate key algorithm
    const keyAlgorithm = leafCert.publicKey.algorithm.name;
    if (keyAlgorithm === 'ECDSA') {
      const namedCurve = (leafCert.publicKey.algorithm as any).namedCurve;
      if (!ANDROID_ATTESTATION_CONFIG.VALID_ECDSA_CURVES.includes(namedCurve)) {
        return { valid: false, message: `Invalid ECDSA curve: ${namedCurve} (expected ${ANDROID_ATTESTATION_CONFIG.VALID_ECDSA_CURVES.join(', ')} per Android CDD)` };
      }
    }
    // } else if (keyAlgorithm.startsWith('RSA')) {
    //   const modulusLength = (leafCert.publicKey.algorithm as any).modulusLength;
    //   if (!ANDROID_ATTESTATION_CONFIG.VALID_RSA_SIZES.includes(modulusLength)) {
    //     return { valid: false, message: `Invalid RSA key size: ${modulusLength} (expected ${ANDROID_ATTESTATION_CONFIG.VALID_RSA_SIZES.join(', ')} bits per Android CDD)` };
    //   }
    // } 
    else {
      return { valid: false, message: `Unsupported key algorithm: ${keyAlgorithm} (expected ECDSA as per Android Key Attestation spec)` };
    }
    
    // Find and validate attestation extension
    const extension = leafCert.extensions?.find((ext: any) => ext.type === ANDROID_ATTESTATION_CONFIG.ATTESTATION_EXTENSION_OID);
    if (!extension) {
      return { valid: false, code: 'missing_attestation_extension', message: 'Missing attestation extension' };
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
 * Validates root certificate against pinned trusted Google roots
 */
function validateTrustedRoot(rootCert: X509Certificate): AttestationResult {
  // In development mode, allow test certificates
  if (process.env.ALLOW_TEST_TOKENS === 'true') {
    const rootSubject = rootCert.subject;
    const isTestRoot = rootSubject.includes('Test');
    if (isTestRoot) {
      logger.info('Accepting test root certificate in development mode');
      return { valid: true };
    }
  }
  
  // Validate against known Google root public keys (cryptographic validation)
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
    
    return { valid: true };
  } catch (error) {
    logger.error('Root public key validation failed', { error: error instanceof Error ? error.message : error });
    return { valid: false, message: 'Failed to validate root certificate public key' };
  }
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

