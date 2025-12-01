import type { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import { randomUUID } from 'node:crypto';
import {Pkcs10CertificateRequest, X509Certificate} from "@peculiar/x509"
import {KeyDescription, SecurityLevel} from '@peculiar/asn1-android'
import { AsnConvert } from '@peculiar/asn1-schema';

const logger = new Logger();

interface IssueReaderCertRequest {
  platform: 'ios' | 'android';
  nonce: string;
  csrPem: string;
  appAttest?: {
    keyId: string;
    attestationObject: string;
    clientDataJSON: string;
  };
  keyAttestationChain?:string[];
  playIntegrityToken?: string;
}

interface IssueReaderCertResponse {
  readerId: string;
  certChain: {
    leaf: string;
    intermediate?: string;
  };
  profile: string;
  notBefore: string;
  notAfter: string;
}

interface ErrorResponse {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export const handler = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  logger.info('Reader certificate service handler invoked', { httpMethod: event.httpMethod, path: event.path });

  if (event.httpMethod !== 'POST' || event.path !== '/issue-reader-cert') {
    logger.warn('Invalid request method or path', { httpMethod: event.httpMethod, path: event.path });
    return createErrorResponse(404, 'not_found', 'Endpoint not found');
  }

  try {
    const request: IssueReaderCertRequest = JSON.parse(event.body || '{}');
    
    // Validate request
    const validationError = validateRequest(request);
    if (validationError) {
      return validationError;
    }

    // Verify nonce
    const nonceValid = await verifyNonce(request.nonce);
    if (!nonceValid) {
      return createErrorResponse(409, 'nonce_replayed', 'Nonce has already been consumed');
    }

    // Verify platform attestation
    const attestationResult = await verifyAttestation(request);
    if (!attestationResult.valid) {
      return createErrorResponse(403, attestationResult.code || 'attestation_failed', attestationResult.message || 'Platform attestation failed');
    }

    // Issue certificate
    const certificate = await issueCertificate(request);
    
    logger.info('Certificate issued successfully', { readerId: certificate.readerId });
    
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-Id': context.awsRequestId,
      },
      body: JSON.stringify(certificate),
    };

  } catch (error) {
    logger.error('Error processing certificate request', { error: error instanceof Error ? error.message : error });
    return createErrorResponse(500, 'internal_error', 'Internal server error issuing certificate');
  }
};

function validateRequest(request: IssueReaderCertRequest): APIGatewayProxyResult | null {
  if (!request.platform || !['ios', 'android'].includes(request.platform)) {
    return createErrorResponse(400, 'bad_request', 'Invalid or missing platform');
  }

  if (!request.nonce) {
    return createErrorResponse(400, 'bad_request', 'Missing nonce');
  }

  if (!request.csrPem || !request.csrPem.includes('BEGIN CERTIFICATE REQUEST')) {
    return createErrorResponse(400, 'bad_request', 'CSR is not a valid PKCS#10 structure', { field: 'csrPem' });
  }

  if (request.platform === 'ios' && !request.appAttest) {
    return createErrorResponse(400, 'bad_request', 'Missing appAttest for iOS platform');
  }

  if (request.platform === 'android' && (!request.keyAttestationChain || !request.playIntegrityToken)) {
    return createErrorResponse(400, 'bad_request', 'Missing keyAttestationChain or playIntegrityToken for Android platform');
  }

  return null;
}

async function verifyNonce(nonce: string): Promise<boolean> {
  // TODO: Implement nonce verification against DynamoDB
  // For now, return true as placeholder
  logger.info('Verifying nonce', { nonce });
  return true;
}

async function verifyAttestation(request: IssueReaderCertRequest): Promise<{ valid: boolean; code?: string; message?: string }> {
  if (request.platform === 'ios') {
    return verifyIOSAttestation(request);
  } else {
    return verifyAndroidAttestation(request);
  }
}

async function verifyIOSAttestation(request: IssueReaderCertRequest): Promise<{ valid: boolean; code?: string; message?: string }> {
  // TODO: Implement iOS App Attest verification
  logger.info('Verifying iOS App Attest', { keyId: request.appAttest?.keyId });
  return { valid: true };
}

async function verifyAndroidAttestation(request: IssueReaderCertRequest): Promise<{ valid: boolean; code?: string; message?: string }> {
  logger.info('Verifying Android attestation', { chainLength: request.keyAttestationChain?.length });

  try {
    // Step 21: Verify Play Integrity Token signature (Google JWKS / keys)
    // const playIntegrityValid = await verifyPlayIntegritySignature(request.playIntegrityToken!);
    // if (!playIntegrityValid) {
    //   return { valid: false, code: 'invalid_play_integrity', message: 'Play Integrity token signature verification failed' };
    // }

    // // Step 22: Check requestDetails.nonce == nonce
    // const nonceValid = await verifyPlayIntegrityNonce(request.playIntegrityToken!, request.nonce);
    // if (!nonceValid) {
    //   return { valid: false, code: 'nonce_mismatch', message: 'Play Integrity nonce does not match request nonce' };
    // }

    // Step 23: Validate app identity
    // const appIdentityValid = await validateAppIdentity(request.playIntegrityToken!);
    // if (!appIdentityValid) {
    //   return { valid: false, code: 'invalid_app_identity', message: 'App identity validation failed' };
    // }

    // Step 24: Validate attestation.x5c cert chain to pinned Google Attestation Root
    // const certChainValid = await validateAttestationCertChain(request.attestation!.x5c);
    // if (!certChainValid) {
    //   return { valid: false, code: 'invalid_cert_chain', message: 'Attestation certificate chain validation failed' };
    // }

    // Step 25: Extract attestedChallenge from extension
    const attestedChallenge = await extractAttestedChallenge(request.keyAttestationChain!);
    if (!attestedChallenge) {
      return { valid: false, code: 'missing_attested_challenge', message: 'Failed to extract attested challenge' };
    }

    // Step 26: Assert attestedChallenge == nonce
    if (attestedChallenge !== request.nonce) {
      return { valid: false, code: 'challenge_mismatch', message: 'Attested challenge does not match nonce' };
    }

   
    // const attestedPublicKey = await extractAttestedPublicKey(request.keyAttestationChain!);
    // if (!attestedPublicKey) {
    //   return { valid: false, code: 'missing_attested_public_key', message: 'Failed to extract attested public key' };
    // }

 
    // const csrPublicKey = await parseCsrPublicKey(request.csrPem);
    // if (!csrPublicKey) {
    //   return { valid: false, code: 'invalid_csr', message: 'Failed to parse CSR public key' };
    // }

     // Step 27: Extract attestedPublicKey from attestation
        // Step 28: Parse csrPem -> csrPublicKey
    // Step 29: Assert attestedPublicKey == csrPublicKey
    // const publicKeysMatch = await comparePublicKeys(request.csrPem, request.keyAttestationChain!);
    // if (!publicKeysMatch) {
    //   return { valid: false, code: 'public_key_mismatch', message: 'Attested public key does not match CSR public key' };
    // }

    // Step 30: Verify verifiedBootState == VERIFIED
     // Step 31: Verify attestationSecurityLevel in {TEE, STRONGBOX}
    const securityLevelValid = await verifySecurityLevel(request.keyAttestationChain!);
    if (!securityLevelValid) {
       return { valid: false, code: 'invalid_security_level', message: 'Attestation security level verification failed' };
    }

    logger.info('Android attestation verification successful');
    return { valid: true };

  } catch (error) {
    logger.error('Error during Android attestation verification', { error: error instanceof Error ? error.message : error });
    return { valid: false, code: 'attestation_error', message: 'Internal error during attestation verification' };
  }
}

// Helper functions for Android attestation verification
// async function verifyPlayIntegritySignature(token: string): Promise<boolean> {
//   try {
//     logger.info('Verifying Play Integrity token signature');
    
//     // Create JWKS instance for Google's public keys
//     const JWKS = jose.createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
    
//     // Verify JWT signature and get payload
//     const { payload } = await jose.jwtVerify(token, JWKS, {
//       issuer: 'https://playintegrity.googleapis.com/',
//     });

//     if (payload) {
//       logger.info('Play Integrity token signature verified successfully');
//       return true;
//     }

//     return false;
//   } catch (error) {
//     const errorMessage = error instanceof Error ? error.message : String(error);
//     logger.error('Error verifying Play Integrity token signature', { error: errorMessage });
    
//     // Handle specific JWKS errors gracefully for testing
//     if (errorMessage.includes('multiple matching keys found') || 
//         errorMessage.includes('Unable to find a signing key') ||
//         errorMessage.includes('JWS signature verification failed')) {
//       logger.warn('JWT verification failed - likely using test/mock token');
//       return false;
//     }
    
//     return false;
//   }
// }

// async function verifyPlayIntegrityNonce(token: string, expectedNonce: string): Promise<boolean> {
//   try {
//     const payload = jose.decodeJwt(token);
//     if (!payload || !payload.requestDetails || !(payload.requestDetails as any).nonce) {
//       logger.error('Invalid Play Integrity token or missing nonce');
//       return false;
//     }
    
//     const tokenNonce = (payload.requestDetails as any).nonce;
//     const matches = tokenNonce === expectedNonce;
    
//     logger.info('Play Integrity nonce verification', { matches });
//     return matches;
//   } catch (error) {
//     logger.error('Error verifying Play Integrity nonce', { error: error instanceof Error ? error.message : error });
//     return false;
//   }
// }

// async function validateAppIdentity(token: string): Promise<boolean> {
//   try {
//     const payload = jose.decodeJwt(token);
//     const appIntegrity = (payload as any).appIntegrity;
    
//     // Check expected package name and app recognition verdict
//     const expectedPackageName = process.env.EXPECTED_PACKAGE_NAME || 'com.example.app';
//     const packageNameValid = appIntegrity?.packageName === expectedPackageName;
//     const recognitionValid = appIntegrity?.appRecognitionVerdict === 'PLAY_RECOGNIZED';
    
//     logger.info('App identity validation', { packageNameValid, recognitionValid });
//     return packageNameValid && recognitionValid;
//   } catch (error) {
//     logger.error('Error validating app identity', { error: error instanceof Error ? error.message : error });
//     return false;
//   }
// }

// async function validateAttestationCertChain(x5c: string[]): Promise<boolean> {
//   try {
//     if (!x5c || x5c.length === 0) {
//       logger.error('Empty certificate chain');
//       return false;
//     }
    
//     logger.info('Validating attestation certificate chain', { chainLength: x5c.length });
    
//     // Parse all certificates in the chain
//     const certificates = [];
//     for (const certB64 of x5c) {
//       const certBuffer = Buffer.from(certB64, 'base64');
//       const asn1 = fromBER(certBuffer.buffer);
//       const cert = new Certificate({ schema: asn1.result });
//       certificates.push(cert);
//     }
    
//     // Verify chain structure
//     if (certificates.length < 2) {
//       logger.error('Certificate chain too short', { length: certificates.length });
//       return false;
//     }
    
//     // Verify each certificate is signed by the next one in the chain
//     for (let i = 0; i < certificates.length - 1; i++) {
//       const cert = certificates[i];
//       const issuerCert = certificates[i + 1];
      
//       // Basic issuer/subject validation
//       const certIssuer = cert.issuer.typesAndValues.map(tv => `${tv.type}=${tv.value.valueBlock.value}`).join(',');
//       const issuerSubject = issuerCert.subject.typesAndValues.map(tv => `${tv.type}=${tv.value.valueBlock.value}`).join(',');
      
//       if (certIssuer !== issuerSubject) {
//         logger.error('Certificate chain validation failed', { 
//           certIndex: i,
//           certIssuer,
//           issuerSubject
//         });
//         return false;
//       }
//     }
    
//     // Check if root certificate is from Google
//     const rootCert = certificates[certificates.length - 1];
//     const rootSubject = rootCert.subject.typesAndValues.map(tv => `${tv.type}=${tv.value.valueBlock.value}`).join(',');
    
//     // Google Hardware Attestation Root CA identifier
//     const isGoogleRoot = rootSubject.includes('Google') && 
//                         (rootSubject.includes('Hardware Attestation') || rootSubject.includes('Android'));
    
//     if (!isGoogleRoot) {
//       logger.warn('Root certificate may not be from Google', { rootSubject });
//       // In production, you might want to return false here
//     }
    
//     logger.info('Certificate chain validation successful', { 
//       chainLength: certificates.length,
//       rootSubject,
//       isGoogleRoot
//     });
    
//     return true;
//   } catch (error) {
//     logger.error('Error validating certificate chain', { error: error instanceof Error ? error.message : error });
//     return false;
//   }
// }

async function extractAttestedChallenge(x5c: string[]): Promise<string | null> {
  if (!x5c || x5c.length === 0) return null;
  
  try {
    const leafCert = x5c[0];
    const certBuffer = new X509Certificate(Buffer.from(leafCert, 'base64'));
      console.log('Subject:', certBuffer.subject);
      console.log('Extensions:', certBuffer.extensions.map(ext => ext.type));
    
    // // Parse certificate using PKI.js
    // const asn1Result = asn1.fromBER(certBuffer);
    // const cert = new Certificate({ schema: asn1Result.result });
    
    // Look for Google attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
    const attestationOid = '1.3.6.1.4.1.11129.2.1.17';
    const extension = certBuffer.extensions?.find((ext: any) => ext.type === attestationOid);
    
    if (!extension) {
      logger.warn('Attestation extension not found');
      return null;
    }
    
    console.log("Extension is ", extension);
    
    // Extract the extnValue from the extension
    const extnValue = extension.value;
    const keyDescription = AsnConvert.parse(extnValue, KeyDescription);
    
    if (keyDescription.attestationChallenge) {
      console.log('Came here')
      const challengeBytes = new Uint8Array(keyDescription.attestationChallenge.buffer);
      console.log(challengeBytes)
      const challenge= Buffer.from(challengeBytes).toString('utf8')
      console.log('Challenge is ', challenge);

//       const plainText = "f18d7ad9-1a0f-4b3f-9235-db6ff194d928";
// const octetString = Buffer.from(plainText, 'utf8');
// console.log('Octet string is ', octetString);
      logger.info('Extracted attested challenge from certificate', { 
        challengeLength: challengeBytes.length 
      });
      
      return challenge;
    }
    
    logger.warn('No attestation challenge found');
    return null;
  }
    
    // Parse extension using direct ASN.1 navigation (like Android repo)
    // try {
    //   const extensionValueBuffer = extension.extnValue.toBER();
    //   const extensionAsn1 = asn1js.fromBER(extensionValueBuffer);
      
    //   if (extensionAsn1.result && 'valueBlock' in extensionAsn1.result) {
    //     const valueBlock = extensionAsn1.result.valueBlock as any;
        
    //     if (valueBlock.value && Array.isArray(valueBlock.value)) {
    //       const keyDescriptionSequence = valueBlock.value;
          
    //       // Android Key Description structure:
    //       // [0] attestationVersion (INTEGER)
    //       // [1] attestationSecurityLevel (ENUMERATED) 
    //       // [2] keymasterVersion (INTEGER)
    //       // [3] keymasterSecurityLevel (ENUMERATED)
    //       // [4] attestationChallenge (OCTET STRING) <- This is what we want
    //       // [5] uniqueId (OCTET STRING)
    //       // [6] softwareEnforced (SEQUENCE)
    //       // [7] teeEnforced (SEQUENCE)
          
    //       if (keyDescriptionSequence.length >= 5) {
    //         const challengeElement = keyDescriptionSequence[4];
            
    //         if (challengeElement.idBlock && 
    //             challengeElement.idBlock.tagClass === 1 && 
    //             challengeElement.idBlock.tagNumber === 4) { // OCTET STRING
              
    //           const challengeBytes = new Uint8Array(challengeElement.valueBlock.valueHex);
    //           const challenge = Buffer.from(challengeBytes).toString('base64');
              
    //           logger.info('Extracted attested challenge from certificate', { 
    //             challengeLength: challengeBytes.length,
    //             sequenceLength: keyDescriptionSequence.length
    //           });
              
    //           return challenge;
    //         }
    //       }
    //     }
    //   }
      
    //   logger.warn('Could not find attestation challenge in expected position');
    //   return null;
    // } 
    // catch (parseError) {
    //   logger.error('Failed to parse attestation extension', { error: parseError instanceof Error ? parseError.message : parseError });
    //   return null;
    // }
  catch (error) {
    logger.error('Error extracting attested challenge', { error: error instanceof Error ? error.message : error });
    return null;
  }
}

// async function extractAttestedPublicKey(keyAttestationChain: string[]): Promise<string | null> {
//   try {
//     if (!keyAttestationChain || keyAttestationChain.length === 0) return null;
    
//     const leafCert = keyAttestationChain[0];
//     const certBuffer = Buffer.from(leafCert, 'base64');
//     const cert = new crypto.X509Certificate(certBuffer);
    
//     // Extract public key from certificate
//     const publicKey = cert.publicKey;
//     const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
//     const publicKeyB64 = publicKeyDer.toString('base64');
    
//     logger.info('Extracted attested public key from certificate');
//     return publicKeyB64;
//   } catch (error) {
//     logger.error('Error extracting attested public key', { error: error instanceof Error ? error.message : error });
//     return null;
//   }
// }

// async function parseCsrPublicKey(csr: string): Promise<string | null> {
//   try {
//     // Extract public key portion from CSR PEM
//     const csrLines = csr.split('\n').filter(line => 
//       !line.includes('BEGIN CERTIFICATE REQUEST') && 
//       !line.includes('END CERTIFICATE REQUEST') &&
//       line.trim() !== ''
//     );
//     const csrBase64 = csrLines.join('');
//     const csrBuffer = Buffer.from(csrBase64, 'base64');
    
//     // Parse CSR using ASN.1 to extract public key
//     const asn1Result = asn1.fromBER(csrBuffer);
//     if (asn1Result.offset === -1) {
//       throw new Error('Failed to parse CSR ASN.1 structure');
//     }
    
//     // Extract public key from CSR structure
//     const csrInfo = (asn1Result.result as any).valueBlock.value[0];
//     const publicKeyInfo = csrInfo.valueBlock.value[2];
//     const publicKeyDer = Buffer.from(publicKeyInfo.toBER());
//     const publicKeyB64 = publicKeyDer.toString('base64');
    
//     logger.info('Parsed CSR public key');
//     return publicKeyB64;
//   } catch (error) {
//     logger.error('Error parsing CSR public key', { error: error instanceof Error ? error.message : error });
//     return null;
//   }
// }

async function comparePublicKeys(csrPem: string, attestationChain: string[]): Promise<boolean> {
  try {
    logger.info('Comparing public keys');

    // Extract SubjectPublicKeyInfo from CSR
    const csr = new Pkcs10CertificateRequest(csrPem);
    const csrSpkiThumbprint = await csr.publicKey.getThumbprint();

    // Extract SubjectPublicKeyInfo from attestation.x5c[0]
    // the leaf certificate must always be in the first element of the x5c list
    const leafCertBuffer = Buffer.from(attestationChain[0], 'base64');
    const leafCert = new X509Certificate(leafCertBuffer);
    const certSpkiThumbprint = await leafCert.publicKey.getThumbprint();

    // Compare bothSubjectPublicKeyInfos to ensure they match
    const compareResult = Buffer.compare(Buffer.from(csrSpkiThumbprint), Buffer.from(certSpkiThumbprint));
    if (compareResult !== 0) {
      logger.warn('Public key in CSR does not match the Public key in the Google Attestation');
      return false;
    }
    
    logger.info('Public keys match successfully');
    return true;
  } catch (error) {
    logger.error('Error comparing public keys', { error: error instanceof Error ? error.message : error });
    return false;
  }
}

async function verifySecurityLevel(x5c: string[]): Promise<boolean> {
  try {
    if (!x5c || x5c.length === 0) return false;
    
    const leafCert = x5c[0];
    const certBuffer = new X509Certificate(Buffer.from(leafCert, 'base64'));
    
    const attestationOid = '1.3.6.1.4.1.11129.2.1.17';
    const extension = certBuffer.extensions?.find((ext: any) => ext.type === attestationOid);
    
    if (!extension) return false;
    
    const keyDescription = AsnConvert.parse(extension.value, KeyDescription);
    
    // Verify that both attestation and keymaster were performed in TEE or StrongBox
    const validSecurityLevels = [SecurityLevel.trustedEnvironment, SecurityLevel.strongBox];
    const isValidLevel = [keyDescription.attestationSecurityLevel, keyDescription.keymasterSecurityLevel]
      .every(level => validSecurityLevels.includes(level));
    
    logger.info('Security level verification', { 
      attestationSecurityLevel: keyDescription.attestationSecurityLevel,
      keymasterSecurityLevel: keyDescription.keymasterSecurityLevel,
      isValid: isValidLevel
    });
    
    return isValidLevel;
  } catch (error) {
    logger.error('Error verifying security level', { error: error instanceof Error ? error.message : error });
    return false;
  }
}

async function issueCertificate(request: IssueReaderCertRequest): Promise<IssueReaderCertResponse> {
  const readerId = `reader-${randomUUID()}`;
  const now = new Date();
  const notAfter = new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes validity

  // TODO: Implement actual certificate issuance
  const mockCertificate: IssueReaderCertResponse = {
    readerId,
    certChain: {
      leaf: `-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----`,
      intermediate: `-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----`,
    },
    profile: 'Reader',
    notBefore: now.toISOString(),
    notAfter: notAfter.toISOString(),
  };

  return mockCertificate;
}

function createErrorResponse(statusCode: number, code: string, message: string, details?: Record<string, unknown>): APIGatewayProxyResult {
  const errorResponse: ErrorResponse = {
    code,
    message,
    ...(details && { details }),
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(errorResponse),
  };
}