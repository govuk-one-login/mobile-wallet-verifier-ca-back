import { getPublicKey, signWithEcdsaSha256 } from '../../../../src/adapters/node-crypto/keyAdapter';

describe('keyAdapter', () => {
  describe('sign', () => {
    it('should pass the call on to the KMS API', async () => {
      // ARRANGE

      // ACT
      await signWithEcdsaSha256(Buffer.from('BUFFER_TO_SIGN'));

      // ASSERT
    });
  });

  describe('getPublicKey', () => {
    it('should pass the call on to the KMS API', async () => {
      // ARRANGE

      // ACT
      getPublicKey();

      // ASSERT
    });
  });
});
