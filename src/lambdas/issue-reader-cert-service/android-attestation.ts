import { Logger } from '@aws-lambda-powertools/logger';
import { X509Certificate, Pkcs10CertificateRequest } from '@peculiar/x509';
import { KeyDescription, SecurityLevel } from '@peculiar/asn1-android';
import { AsnConvert } from '@peculiar/asn1-schema';
import * as jose from 'jose';
import { IssueReaderCertRequest, AttestationResult } from './types.ts';

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
      () => verifyPlayIntegrityToken(request.playIntegrityToken!, request.nonce),
      () => validateAttestationCertChain(request.keyAttestationChain!),
      () => verifyAttestationExtension(request.keyAttestationChain!, request.nonce),
      () => comparePublicKeys(request.csrPem, request.keyAttestationChain!)
    ];

    for (const validation of validations) {
      const result = await validation();
      if (typeof result === 'boolean' && !result) {
        return { valid: false, code: 'validation_failed', message: 'Validation step failed' };
      }
      if (typeof result === 'object' && !result.valid) {
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
 * Validates Android key attestation certificate chain
 */
async function validateAttestationCertChain(x5c: string[]): Promise<AttestationResult> {
  try {
    if (!x5c || x5c.length === 0) {
      return { valid: false, message: 'Certificate chain is empty' };
    }
    
    const certificates = x5c.map(certB64 => new X509Certificate(Buffer.from(certB64, 'base64')));
    if (certificates.length < 2) {
      return { valid: false, message: `Certificate chain too short (${certificates.length} certificates, minimum 2 required)` };
    }
    
    const leafCert = certificates[0];
    
    const leafResult = validateLeafCertificate(leafCert);
    if (!leafResult.valid) {
      return { valid: false, message: `Leaf certificate validation failed: ${leafResult.message}` };
    }
    
    const chainResult = validateCertificateChainValidity(certificates);
    if (!chainResult.valid) {
      return { valid: false, message: `Certificate chain validity failed: ${chainResult.message}` };
    }
    
    const rootResult = validateRootCertificate(certificates[certificates.length - 1]);
    if (!rootResult.valid) {
      return { valid: false, message: `Root certificate validation failed: ${rootResult.message}` };
    }
    
    return { valid: true };
  } catch (error) {
    logger.error('Error validating certificate chain', { error: error instanceof Error ? error.message : error });
    return { valid: false, message: `Certificate chain parsing error: ${error instanceof Error ? error.message : 'Unknown error'}` };
  }
}

/**
 * Validates leaf certificate (algorithm, extensions, validity)
 */
function validateLeafCertificate(leafCert: X509Certificate): AttestationResult {
  const now = new Date();
  
  if (now < leafCert.notBefore || now > leafCert.notAfter) {
    return { valid: false, message: `Certificate not valid at current time (valid from ${leafCert.notBefore} to ${leafCert.notAfter})` };
  }
  
  const attestationOid = '1.3.6.1.4.1.11129.2.1.17';
  if (!leafCert.extensions?.some((ext: any) => ext.type === attestationOid)) {
    return { valid: false, message: 'Missing Android attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)' };
  }
  
  const keyAlgorithm = leafCert.publicKey.algorithm.name;
  
  //Richa - TO CHECK if have any view on adding checks for keyAlgo/curve?
  if (keyAlgorithm === 'ECDSA') {
    const namedCurve = (leafCert.publicKey.algorithm as any).namedCurve;
    // P-256 is required by Android CDD, others are optional but commonly supported
    const validCurves = ['P-256', 'P-384', 'P-521'];
    if (!validCurves.includes(namedCurve)) {
      return { valid: false, message: `Invalid ECDSA curve: ${namedCurve} (expected P-256, P-384, or P-521 per Android CDD)` };
    }
  } else if (keyAlgorithm === 'RSASSA-PKCS1-v1_5') {
    const modulusLength = (leafCert.publicKey.algorithm as any).modulusLength;
    // 2048-bit RSA is required by Android CDD, larger sizes are optional
    const validSizes = [2048, 3072, 4096];
    if (!validSizes.includes(modulusLength)) {
      return { valid: false, message: `Invalid RSA key size: ${modulusLength} (expected 2048, 3072, or 4096 bits per Android CDD)` };
    }
  } else {
    return { valid: false, message: `Unsupported key algorithm: ${keyAlgorithm} (expected ECDSA or RSA per Android Key Attestation spec)` };
  }
  
  return { valid: true };
}

/**
 * Validates certificate chain time validity
 */
function validateCertificateChainValidity(certificates: X509Certificate[]): AttestationResult {
  const now = new Date();
  
  for (let i = 0; i < certificates.length; i++) {
    const cert = certificates[i];
    if (now < cert.notBefore || now > cert.notAfter) {
      return { valid: false, message: `Certificate ${i} not valid at current time (valid from ${cert.notBefore} to ${cert.notAfter})` };
    }
  }
  
  return { valid: true };
}

/**
 * Validates root certificate is from Google or test CA
 */
//TO DO Remove Test check once valid payload is available
function validateRootCertificate(rootCert: X509Certificate): AttestationResult {
  const rootSubject = rootCert.subject;
  const isGoogleRoot = rootSubject.includes('Google');
  const isTestRoot = rootSubject.includes('Test');
  
  if (!isGoogleRoot && !isTestRoot) {
    return { valid: false, message: `Root certificate not from Google or test CA (subject: ${rootSubject})` };
  }
  
  logger.info('Root certificate validation passed', { rootSubject, isGoogleRoot, isTestRoot });
  return { valid: true };
}

/**
 * Verifies attestation extension (challenge and security levels)
 */
async function verifyAttestationExtension(x5c: string[], expectedNonce: string): Promise<AttestationResult> {
  try {
    const leafCert = new X509Certificate(Buffer.from(x5c[0], 'base64'));
    const attestationOid = '1.3.6.1.4.1.11129.2.1.17';
    const extension = leafCert.extensions?.find((ext: any) => ext.type === attestationOid);
    
    if (!extension) {
      return { valid: false, code: 'missing_attestation_extension', message: 'Missing attestation extension' };
    }
    
    const keyDescription = AsnConvert.parse(extension.value, KeyDescription);
    
    // Verify attested challenge
    if (!keyDescription.attestationChallenge) {
      return { valid: false, code: 'missing_attested_challenge', message: 'Failed to extract attested challenge' };
    }
    
    const challengeBytes = new Uint8Array(keyDescription.attestationChallenge.buffer);
    const attestedChallenge = Buffer.from(challengeBytes).toString('utf8');
    
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
    logger.error('Error verifying attestation extension', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'attestation_extension_error', message: 'Failed to verify attestation extension' };
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

