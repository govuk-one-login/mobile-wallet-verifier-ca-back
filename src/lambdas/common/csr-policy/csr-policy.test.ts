import { describe, it, expect } from 'vitest';
import {
  BASIC_CONSTRAINTS_OID,
  CSR_EC_CURVE,
  CSR_SUBJECT_POLICY,
} from './csr-policy';

describe('CSR Subject Policy', () => {
  describe('BASIC_CONSTRAINTS_OID', () => {
    it('Is "2.5.29.19"', () => {
      expect(BASIC_CONSTRAINTS_OID).toEqual('2.5.29.19');
    });
  });

  describe('CSR_EC_CURVE', () => {
    it('Is "P-384"', () => {
      expect(CSR_EC_CURVE).toEqual('P-384');
    });
  });

  describe('CSR_SUBJECT_POLICY', () => {
    describe('C', () => {
      it('Is "GB"', () => {
        expect(CSR_SUBJECT_POLICY.C).toEqual('GB');
      });
    });

    describe('O', () => {
      it('Is "Government Digital Service"', () => {
        expect(CSR_SUBJECT_POLICY.O).toEqual('Government Digital Service');
      });
    });
  });
});
