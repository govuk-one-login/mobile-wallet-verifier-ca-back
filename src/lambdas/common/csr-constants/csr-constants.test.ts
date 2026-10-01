import { describe, it, expect } from 'vitest';
import {
  BASIC_CONSTRAINTS_OID,
  CSR_POLICY,
  DEFAULT_CSR_CURVE,
  EXTENDED_KEY_USAGE_OID,
  KEY_USAGE_OID,
  NAME_CONSTRAINTS_OID,
  SUPPORTED_CURVES_LABEL,
} from './csr-constants';

describe('BASIC_CONSTRAINTS_OID', () => {
  it('Is "2.5.29.19"', () => {
    expect(BASIC_CONSTRAINTS_OID).toEqual('2.5.29.19');
  });
});

describe('KEY_USAGE_OID', () => {
  it('Is "2.5.29.15"', () => {
    expect(KEY_USAGE_OID).toEqual('2.5.29.15');
  });
});

describe('EXTENDED_KEY_USAGE_OID', () => {
  it('Is "2.5.29.37"', () => {
    expect(EXTENDED_KEY_USAGE_OID).toEqual('2.5.29.37');
  });
});

describe('NAME_CONSTRAINTS_OID', () => {
  it('Is "2.5.29.30"', () => {
    expect(NAME_CONSTRAINTS_OID).toEqual('2.5.29.30');
  });
});

describe('CSR Policy', () => {
  describe('curves', () => {
    it('Supports P-256 and P-384', () => {
      expect(CSR_POLICY.curves).toEqual(['P-256', 'P-384']);
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

  describe('keyUsage', () => {
    describe('digitalSignature', () => {
      it('Is 1', () => {
        expect(CSR_POLICY.keyUsage.digitalSignature).toEqual(1);
      });
    });
  });

  describe('extendedKeyUsage', () => {
    describe('mobileDocumentReaderAuthentication', () => {
      it('Is "1.0.18013.5.1.6"', () => {
        expect(
          CSR_POLICY.extendedKeyUsage.mobileDocumentReaderAuthentication,
        ).toEqual('1.0.18013.5.1.6');
      });
    });
  });
});

describe('SUPPORTED_CURVES_LABEL', () => {
  it('Is "P-256 or P-384"', () => {
    expect(SUPPORTED_CURVES_LABEL).toEqual('P-256 or P-384');
  });
});

describe('DEFAULT_CSR_CURVE', () => {
  it('Is "P-384" (mock generator keeps P-384)', () => {
    expect(DEFAULT_CSR_CURVE).toEqual('P-384');
  });
});
