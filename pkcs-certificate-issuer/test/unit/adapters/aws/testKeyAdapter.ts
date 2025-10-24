import { generateEcKeyPair, signWithPrivateKey } from '../../../../src/adapters/node-crypto/keyAdapter';

const { publicKey, privateKey } = generateEcKeyPair();
console.log('Public Key:\n', publicKey);
console.log('Private Key:\n', privateKey);

const payload = 'Hello, world!';
const signature = signWithPrivateKey(privateKey, payload);
console.log('Signature (base64):', signature.toString('base64'));