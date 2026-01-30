import { Logger } from '@aws-lambda-powertools/logger';
import { X509Certificate, BasicConstraintsExtension } from '@peculiar/x509';
import { KeyDescription, SecurityLevel } from '@peculiar/asn1-android';
import { AsnConvert } from '@peculiar/asn1-schema';
import { AttestationResult } from './types';
//import { validatePlayIntegritySignature, validatePlayIntegrityPayload } from './play-integrity-validator';

import { ANDROID_ATTESTATION_CONFIG } from '../../../common/const';

let certificateCache: { certificates: string[]; expiry: number } | null = null;

/**
 * Fetches trusted root certificates from Google's Android attestation API
 * @returns Array of PEM-formatted root certificates or null if fetch fails
 */
async function getTrustedRootCertificates(): Promise<string[] | null> {
  const now = Date.now();

  if (certificateCache && now < certificateCache.expiry) {
    return certificateCache.certificates;
  }

  try {
    const response = await fetch('https://android.googleapis.com/attestation/root');
    if (!response.ok) {
      throw new Error(`Failed to fetch root certificates: ${response.status}`);
    }
    const data = (await response.json()) as { entries: Record<string, string> };
    const certificates = Object.values(data.entries);

    certificateCache = {
      certificates,
      expiry: now + 3600000, // 1 hour
    };

    return certificates;
  } catch (error) {
    logger.error('Failed to fetch Google root certificates', {
      error: error instanceof Error ? error.message : error,
    });
    return null;
  }
}

const logger = new Logger();

/**
 * Verifies Android attestation including Play Integrity and key attestation chain
 * @param request - The certificate request containing Android attestation data
 * @returns Attestation verification result
 */
// export async function verifyFirebaseAttestation(request: IssueReaderCertRequest): Promise<AttestationResult> {
//   //logger.info('Verifying Android attestation', { chainLength: request.keyAttestationChain?.length });
//
//   try {
//     const validations = [
//       () => verifyPlayIntegrityToken(request.clientAttestationJwt!), // Verify Play Integrity token signature and payload
//       // () => validateCSRAndPublicKey(request.csrPem, request.keyAttestationChain!), // Validate CSR and ensure it matches attested key
//     ];
//
//     for (const validation of validations) {
//       const result = await validation();
//
//       if (!result.valid) {
//         console.log(result.message);
//         return result;
//       }
//     }
//
//     logger.info('Android attestation verification successful');
//     return { valid: true };
//   } catch (error) {
//     logger.error('Error during Android attestation verification', {
//       error: error instanceof Error ? error.message : error,
//     });
//     return { valid: false, code: 'attestation_error', message: 'Internal error during attestation verification' };
//   }
// }

/**
 * Verifies Play Integrity token (signature, nonce, and payload validation)
 */
// async function verifyPlayIntegrityToken(token: string): Promise<AttestationResult> {
//   try {
//     const signatureResult = await validatePlayIntegritySignature(token);
//     if (!signatureResult.valid) return signatureResult;
//
//     const payload = jose.decodeJwt(token);
//     return validatePlayIntegrityPayload(payload);
//   } catch (error) {
//     const errorMessage = error instanceof Error ? error.message : String(error);
//
//     // Handle specific Play Integrity error codes
//     if (errorMessage.includes('INTEGRITY_TOKEN_PROVIDER_INVALID')) {
//       return {
//         valid: false,
//         code: 'integrity_token_provider_invalid',
//         message: 'Play Integrity API is not available on this device',
//       };
//     }
//
//     logger.error('Error verifying Play Integrity token', { error: errorMessage });
//     return { valid: false, code: 'invalid_play_integrity', message: 'Play Integrity token verification failed' };
//   }
// }

/**
 * Validates all certificate properties (All certs in Android chain are valid and poperly formed)
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function validateCertificates(x5c: string[]): Promise<AttestationResult> {
  try {
    const certificates = parseCertificates(x5c);
    if (!certificates.valid) return certificates;

    const validations = [
      () => validateCertificateValidity(certificates.certificates!),
      () => validateSignatures(certificates.certificates!),
      () => validateCertificateExtensions(certificates.certificates!),
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
  // Validate certificate format and parse
  const certificates: X509Certificate[] = [];
  for (let i = 0; i < x5c.length; i++) {
    try {
      const derBuffer = Buffer.from(x5c[i], 'base64');
      certificates.push(new X509Certificate(derBuffer));
    } catch {
      return { valid: false, message: `Certificate ${i} is not valid X.509 ASN.1 format` };
    }
  }

  return { valid: true, certificates };
}

function validateCertificateExtensions(certificates: X509Certificate[]): AttestationResult {
  let attestationExtCount = 0;

  for (let i = 0; i < certificates.length; i++) {
    const cert = certificates[i];
    const basicConstraintsExts =
      cert.extensions?.filter(
        (ext) => (ext as { type: string }).type === ANDROID_ATTESTATION_CONFIG.BASIC_CONSTRAINTS_OID,
      ) || [];

    attestationExtCount +=
      cert.extensions?.filter(
        (ext) => (ext as { type: string }).type === ANDROID_ATTESTATION_CONFIG.ATTESTATION_EXTENSION_OID,
      ).length || 0;

    if (basicConstraintsExts.length > 1) {
      return { valid: false, message: `Certificate ${i} has multiple Basic Constraints extensions` };
    }

    const constraintResult = validateConstraints(basicConstraintsExts, i);
    if (!constraintResult.valid) return constraintResult;
  }

  return attestationExtCount === 1
    ? { valid: true }
    : { valid: false, message: `Expected exactly 1 attestation extension, found ${attestationExtCount}` };
}

function validateConstraints(basicConstraintsExts: { rawData: ArrayBuffer }[], certIndex: number): AttestationResult {
  const isLeaf = certIndex === 0;

  if (isLeaf && basicConstraintsExts.length === 0) return { valid: true };

  if (!isLeaf && basicConstraintsExts.length === 0) {
    return { valid: false, message: `Certificate ${certIndex} missing Basic Constraints extension` };
  }

  const basicConstraints = new BasicConstraintsExtension(basicConstraintsExts[0].rawData);
  const shouldBeCA = !isLeaf;

  return basicConstraints.ca === shouldBeCA
    ? { valid: true }
    : {
        valid: false,
        message: isLeaf ? 'Leaf certificate incorrectly marked as CA' : `Certificate ${certIndex} not marked as CA`,
      };
}

async function validateSignatures(certificates: X509Certificate[]): Promise<AttestationResult> {
  for (let i = 0; i < certificates.length - 1; i++) {
    const cert = certificates[i];
    const issuerCert = certificates[i + 1];

    // Validate DN chain
    if (cert.issuer !== issuerCert.subject) {
      return {
        valid: false,
        message: `Certificate ${i} issuer DN does not match issuing certificate ${i + 1} subject DN`,
      };
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
  const topCert = certificates.at(-1)!;
  const trustedRootCertificates = await getTrustedRootCertificates();
  if (!trustedRootCertificates) {
    return { valid: false, message: 'Failed to fetch trusted root certificates from Google API' };
  }
  for (const trustedRootPem of trustedRootCertificates) {
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

  return {
    valid: false,
    message: `Certificate chain does not link to trusted Google root. Expected issuer: ${topCert.issuer}`,
  };
}

function validateCertificateValidity(certificates: X509Certificate[]): AttestationResult {
  const now = new Date();

  for (let i = 0; i < certificates.length; i++) {
    const cert = certificates[i];
    if (now < cert.notBefore || now > cert.notAfter) {
      let certType: string;
      if (i === 0) {
        certType = 'Leaf';
      } else if (i === certificates.length - 1) {
        certType = 'Root';
      } else {
        certType = 'Intermediate';
      }
      return {
        valid: false,
        message: `${certType} certificate not valid at current time (valid from ${cert.notBefore} to ${cert.notAfter})`,
      };
    }
  }

  return { valid: true };
}

/**
 * Verifies Key attestation challenge and validates leaf certificate
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function verifyAttestationChallenge(x5c: string[], expectedNonce: string): Promise<AttestationResult> {
  try {
    const leafCert = new X509Certificate(Buffer.from(x5c[0], 'base64'));

    // Find and validate attestation extension
    const extension = leafCert.extensions?.find(
      (ext: { type: string }) => ext.type === ANDROID_ATTESTATION_CONFIG.ATTESTATION_EXTENSION_OID,
    );
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
    const validSecurityLevels = new Set([SecurityLevel.trustedEnvironment, SecurityLevel.strongBox]);
    const validLevels = [keyDescription.attestationSecurityLevel, keyDescription.keymasterSecurityLevel].every(
      (level) => validSecurityLevels.has(level),
    );
    if (!validLevels) {
      return {
        valid: false,
        code: 'invalid_security_level',
        message: 'Attestation security level verification failed',
      };
    }

    return { valid: true };
  } catch (error) {
    logger.error('Error verifying attestation challenge', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'attestation_extension_error', message: 'Failed to verify attestation challenge' };
  }
}

/**
 * Validates CSR content and verifies it matches the attested Android device public key
 * Extracts the public key from the leaf certificate in the attestation chain
 */

// will be worked in CSR ticket

// async function validateCSRAndPublicKey(csrPem: string, attestationChain: string[]): Promise<AttestationResult> {
//   try {
//     const leafCert = new X509Certificate(Buffer.from(attestationChain[0], 'base64'));
//     return await validateCSRContent(csrPem, leafCert.publicKey);
//   } catch (error) {
//     logger.error('Error validating CSR against Android attestation', {
//       error: error instanceof Error ? error.message : error,
//     });
//     return { valid: false, code: 'invalid_csr', message: 'Failed to validate CSR against Android attestation chain' };
//   }
// }
