import { describe, it, expect } from 'vitest';

describe('Certificate Service', () => {
  describe('issueCertificate and getCertificate', () => {
    it('should be defined and callable', async () => {
      const { issueCertificate, getCertificate } =
        await import('./certificate-service.ts');
      expect(issueCertificate).toBeDefined();
      expect(getCertificate).toBeDefined();
      expect(typeof issueCertificate).toBe('function');
      expect(typeof getCertificate).toBe('function');
    });
  });
});
