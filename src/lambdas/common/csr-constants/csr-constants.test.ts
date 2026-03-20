import { describe, it, expect } from 'vitest';
import { BASIC_CONSTRAINTS_OID, CSR_POLICY } from './csr-constants';

describe('BASIC_CONSTRAINTS_OID', () => {
  it('Is "2.5.29.19"', () => {
    expect(BASIC_CONSTRAINTS_OID).toEqual('2.5.29.19');
  });
});

describe('CSR Policy', () => {
  describe('curve', () => {
    it('Is "P-384"', () => {
      expect(CSR_POLICY.curve).toEqual('P-384');
    });
  });

  describe('subject', () => {
    describe('C', () => {
      it('Is "GB"', () => {
        expect(CSR_POLICY.subject.C).toEqual('GB');
      });
    });

    describe('O', () => {
      it('Is "Government Digital Service"', () => {
        expect(CSR_POLICY.subject.O).toEqual('Government Digital Service');
      });
    });
  });
});
