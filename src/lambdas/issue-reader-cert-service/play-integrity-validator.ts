import * as jose from 'jose';
import { Logger } from '@aws-lambda-powertools/logger';
import { AttestationResult } from './types';


const logger = new Logger();

// Validates the Play Integrity token's signature using Google's JWKS (mock for now)
export async function validatePlayIntegritySignature(token: string): Promise<AttestationResult> {
  if (process.env.ALLOW_TEST_TOKENS === 'true') {
    logger.info('Skipping Google JWKS verification in development mode');
    return { valid: true };
  }

  const header = jose.decodeProtectedHeader(token);
  if (!header.kid) {
    return { valid: false, code: 'invalid_play_integrity', message: 'JWT header missing kid (key ID)' };
  }
  
  //Pin certificate in secrets manager instead of calling google JWKS every time
  const JWKS = jose.createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'), {
    cooldownDuration: 30000,
    cacheMaxAge: 600000
  });
  
  await jose.jwtVerify(token, JWKS, {
    issuer: 'https://playintegrity.googleapis.com/',
    algorithms: ['RS256']
  });

  return { valid: true };
}

export function validatePlayIntegrityPayload(payload: any, expectedNonce: string): AttestationResult {
  const { requestDetails, appIntegrity, deviceIntegrity, accountDetails } = payload;
  
  // Verify nonce
  if (requestDetails?.nonce !== expectedNonce) {
    return { valid: false, code: 'nonce_mismatch', message: 'Play Integrity nonce does not match request nonce' };
  }
  //Richa - TO CHECK is this check needed, in sequence diag?
  //Get expected paackge name from verifier app
  // Validate app identity
  const expectedPackageName = process.env.EXPECTED_PACKAGE_NAME || 'org.multipaz.identityreader';
  if (appIntegrity?.packageName !== expectedPackageName) {
    return { valid: false, code: 'invalid_package', message: 'Package name mismatch' };
  }
  
  if (appIntegrity?.appRecognitionVerdict !== 'PLAY_RECOGNIZED') {
    return { valid: false, code: 'app_not_recognized', message: 'App not recognized by Play Store' };
  }
  
  //Richa - TO CHECK is this check needed, not in sequence diag? good to keep
  // Validate device integrity
  const deviceVerdicts = deviceIntegrity?.deviceRecognitionVerdict || [];
  const hasValidDevice = deviceVerdicts.includes('MEETS_DEVICE_INTEGRITY') || 
                        deviceVerdicts.includes('MEETS_BASIC_INTEGRITY');
  if (!hasValidDevice) {
    return { valid: false, code: 'device_integrity_failed', message: 'Device integrity check failed' };
  }
  
  //Richa - TO CHECK is this check needed, not in sequence diag? good to keep
  // Validate app licensing
  if (accountDetails?.appLicensingVerdict === 'UNEVALUATED') {
    logger.warn('App licensing could not be evaluated');
  } else if (accountDetails?.appLicensingVerdict !== 'LICENSED') {
    return { valid: false, code: 'app_not_licensed', message: 'App is not properly licensed' };
  }
  
  return { valid: true };
}