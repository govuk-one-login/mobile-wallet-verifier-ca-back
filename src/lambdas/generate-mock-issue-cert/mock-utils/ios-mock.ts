import { generateCSR, createIntermediateCA, createIOSAttestationCert } from './certificate-generator.ts';
import { IOSKeyProvider } from './ios-key-provider.ts';
import * as crypto from 'node:crypto';
import { encode } from 'cborg';

export interface MockIOSRequest {
  nonce: string;
  csrPem: string;
  keyId: string;
  attestationObject: string;
  clientDataJSON: string;
}

export class IOSDeviceSimulator {
  private keyProvider: IOSKeyProvider;

  constructor() {
    this.keyProvider = new IOSKeyProvider();
  }

  async generateMockRequest(nonce: string): Promise<MockIOSRequest> {
    const keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const publicKeyDer = crypto.createPublicKey(keyPair.publicKey).export({ type: 'spki', format: 'der' });
    const keyId = crypto.createHash('sha256').update(publicKeyDer).digest('base64');

    // Create attestation object with the same key pair
    const attestationObject = await this.createAttestationObject(keyPair.publicKey, keyPair.privateKey, nonce, keyId);
    
    const csr = await generateCSR({
      privateKeyPem: keyPair.privateKey,
      publicKeyPem: keyPair.publicKey,
      subject: {
        countryName: 'US',
        organizationName: 'Apple',
        commonName: 'iOS Device Key',
      },
    });

    const clientDataJSON = Buffer.from(JSON.stringify({ challenge: nonce, origin: 'ios-app' })).toString('base64');

    return {
      nonce,
      csrPem: csr.csrPem,
      keyId,
      attestationObject,
      clientDataJSON,
    };
  }

  private async createAttestationObject(publicKeyPem: string, privateKeyPem: string, nonce: string, keyId: string): Promise<string> {
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const jwk = publicKey.export({ format: 'jwk' }) as crypto.JsonWebKey;
    
    const authData = this.createAuthData(jwk, keyId);
    
    const rootCA = await this.keyProvider.getRootCA();
    const intermediateKeys = await this.keyProvider.getIntermediateCAKeys();
    
    // Use the same key pair for the certificate as in the authenticator data
    const deviceKeys = {
      privateKeyPem: privateKeyPem,
      publicKeyPem: publicKeyPem
    };

    const intermediateCert = await createIntermediateCA(intermediateKeys, rootCA.keyPair, rootCA.certificatePem);
    const leafCert = await createIOSAttestationCert(deviceKeys, intermediateKeys, intermediateCert, nonce, authData);

    const { X509Certificate } = await import('@peculiar/x509');
    const leafDer = new X509Certificate(leafCert).rawData;
    const intermediateDer = new X509Certificate(intermediateCert).rawData;
    
    const attestation = {
      fmt: 'apple-appattest',
      attStmt: {
        x5c: [Buffer.from(leafDer), Buffer.from(intermediateDer)],
        receipt: Buffer.from('mock-receipt'),
      },
      authData: new Uint8Array(authData),
    };

    return this.encodeCBOR(attestation);
  }

  private createAuthData(jwk: crypto.JsonWebKey, keyId: string): Buffer {
    const rpIdHash = crypto.createHash('sha256').update('appattestdevelop').digest();
    const flags = Buffer.from([0x41]);
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(0, 0);
    const aaguid = Buffer.alloc(16);
    aaguid.write('appattestdevelop', 0, 16, 'utf8');
    
    // Use keyId as credential ID (base64 decoded)
    const credId = Buffer.from(keyId, 'base64');
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(credId.length, 0);
    
    const publicKeyCBOR = this.encodePublicKeyCBOR(jwk);

    const authData = Buffer.concat([rpIdHash, flags, counter, aaguid, credIdLen, credId, publicKeyCBOR]);
    console.log('AuthData created:', { length: authData.length, publicKeyCBORLength: publicKeyCBOR.length });
    return authData;
  }

  private encodePublicKeyCBOR(jwk: crypto.JsonWebKey): Buffer {
    const x = Buffer.from(jwk.x!, 'base64url');
    const y = Buffer.from(jwk.y!, 'base64url');
    
    const coseKey = new Map();
    coseKey.set(1, 2);
    coseKey.set(3, -7);
    coseKey.set(-1, 1);
    coseKey.set(-2, new Uint8Array(x));
    coseKey.set(-3, new Uint8Array(y));
    
    return Buffer.from(encode(coseKey));
  }

  private encodeCBOR(obj: any): string {
    const encoded = encode(obj);
    return Buffer.from(encoded).toString('base64');
  }
}
