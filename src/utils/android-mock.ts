import { generateCSR, createIntermediateCA, createLeafCertWithAttestation } from './certificate-generator.ts';
import { PlayIntegritySigner, PlayIntegrityPayload } from './play-integrity-signer.ts';
import { AndroidKeyProvider } from './android-key-provider.ts';
import { PLAY_INTEGRITY_KEYS_SECRET } from '../../scripts/setup-android-infrastructure.ts';

export interface AndroidDeviceSimulation {
  deviceKeyPair: { privateKeyPem: string; publicKeyPem: string };
  playIntegrityKeyPair: { privateKeyPem: string; publicKeyPem: string };
}

export interface MockAndroidRequest {
  nonce: string;
  csrPem: string;
  keyAttestationChain: string[];
  playIntegrityToken: string;
}

export class AndroidDeviceSimulator {
  private keyProvider: AndroidKeyProvider;
  private playIntegritySigner: PlayIntegritySigner;

  constructor() {
    this.keyProvider = new AndroidKeyProvider();
    this.playIntegritySigner = new PlayIntegritySigner();
  }

  async generateMockRequest(nonce: string): Promise<MockAndroidRequest> {
    const deviceKeys = await this.keyProvider.getDeviceKeys();
    
    // Generate CSR using device keys (simulates app generating CSR)
    const csr = await generateCSR({
      privateKeyPem: deviceKeys.privateKeyPem,
      publicKeyPem: deviceKeys.publicKeyPem,
      subject: {
        countryName: 'UK',
        organizationName: 'GDS',
        commonName: 'Android Device Key'
      }
    });

    // Generate Play Integrity token using separate keys
    const playIntegrityToken = await this.signPlayIntegrityToken(nonce);

    // Generate test CA chain with nonce in attestation extension
    const keyAttestationChain = await this.generateTestCAChain(nonce);

    return {
      nonce,
      csrPem: csr.csrPem,
      keyAttestationChain,
      playIntegrityToken
    };
  }

  private async signPlayIntegrityToken(nonce: string): Promise<string> {
    const payload: PlayIntegrityPayload = {
      requestDetails: {
        requestPackageName: 'org.multipaz.identityreader',
        timestampMillis: Date.now().toString(),
        nonce
      },
      appIntegrity: {
        appRecognitionVerdict: 'PLAY_RECOGNIZED',
        packageName: 'org.multipaz.identityreader',
        certificateSha256Digest: ['abc123'],
        versionCode: '1'
      },
      deviceIntegrity: {
        deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY']
      },
      accountDetails: {
        appLicensingVerdict: 'LICENSED'
      }
    };

    return await this.playIntegritySigner.signToken(payload, PLAY_INTEGRITY_KEYS_SECRET);
  }

  private async generateTestCAChain(nonce: string): Promise<string[]> {
    const rootCA = await this.keyProvider.getRootCA();
    const intermediateKeys = await this.keyProvider.getIntermediateCAKeys();
    const leafKeys = await this.keyProvider.getLeafCAKeys();

    // Create certificates using stored keys
    const intermediateCert = await createIntermediateCA(intermediateKeys, rootCA.keyPair, rootCA.certificatePem);
    const leafCert = await createLeafCertWithAttestation(leafKeys, intermediateKeys, intermediateCert, nonce);

    // Convert to base64 for keyAttestationChain
    return [
      Buffer.from(leafCert).toString('base64'),
      Buffer.from(intermediateCert).toString('base64'),
      Buffer.from(rootCA.certificatePem).toString('base64')
    ];
  }

}