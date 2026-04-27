import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  afterEach,
  MockInstance,
} from 'vitest';
import { validateLeafCertificate } from './validate-leaf-certificate.ts';
import '../../../tests/testUtils/matchers.ts';
import { emptySuccess, errorResult, Result } from '../common/result/result.ts';
import { createValidCertPem } from '../../../tests/testUtils/create-valid-cert-pem.ts';
import { AsnConvert } from '@peculiar/asn1-schema';

describe('validateLeafCertificate', () => {
  let consoleErrorSpy: MockInstance;
  let result: Result<void, string>;

  beforeEach(async () => {
    consoleErrorSpy = vi.spyOn(console, 'error');
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Given Leaf certificate verification fails', () => {
    describe('Given certificate is not valid X.509 format', () => {
      beforeEach(async () => {
        result = await validateLeafCertificate(
          await createValidCertPem({ invalidX509: true }),
        );
      });
      it('Logs error', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode:
            'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
          errorMessage: 'Certificate not valid X.509 format',
        });
      });

      it('Returns an error result', () => {
        expect(result).toEqual(
          errorResult('Certificate not valid X.509 format'),
        );
      });
    });

    describe('Given certificate version is not v3', () => {
      beforeEach(async () => {
        const validCert = await createValidCertPem();
        vi.spyOn(AsnConvert, 'parse').mockReturnValue({
          tbsCertificate: {
            version: 0, // v1 instead of v3 (2)
            serialNumber: new ArrayBuffer(8), // Valid serial number
          },
        } as any);
        result = await validateLeafCertificate(validCert);
      });

      afterEach(() => {
        vi.restoreAllMocks();
      });

      it('Logs error', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode:
            'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
          errorMessage: 'Certificate version must be v3',
        });
      });

      it('Returns an error result', () => {
        expect(result).toEqual(errorResult('Certificate version must be v3'));
      });
    });

    describe('Given certificate serial number validation fails', () => {
      describe('Given certificate has missing serial number', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2, // Valid version
              serialNumber: null, // Missing serial number
            },
          } as any);
          result = await validateLeafCertificate(validCert);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate serial number must be present',
          });
        });

        it('Returns serial number missing error', () => {
          expect(result).toEqual(
            errorResult('Certificate serial number must be present'),
          );
        });
      });

      describe('Given certificate has empty serial number', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2, // Valid version
              serialNumber: new ArrayBuffer(0), // Empty serial number
            },
          } as any);
          result = await validateLeafCertificate(validCert);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate serial number must be present',
          });
        });

        it('Returns serial number empty error', () => {
          expect(result).toEqual(
            errorResult('Certificate serial number must be present'),
          );
        });
      });

      describe('Given certificate has serial number exceeding 20 octets', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          const longSerial = new ArrayBuffer(21); // 21 bytes > 20 octets limit
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2, // Valid version
              serialNumber: longSerial,
            },
          } as any);
          result = await validateLeafCertificate(validCert);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate serial number must not exceed 20 octets',
          });
        });

        it('Returns serial number length error', () => {
          expect(result).toEqual(
            errorResult('Certificate serial number must not exceed 20 octets'),
          );
        });
      });

      describe('Given certificate has zero serial number', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          const zeroSerial = new ArrayBuffer(8);
          // ArrayBuffer is initialized with zeros by default
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2, // Valid version
              serialNumber: zeroSerial,
            },
          } as any);
          result = await validateLeafCertificate(validCert);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate serial number must be non-zero',
          });
        });

        it('Returns serial number zero error', () => {
          expect(result).toEqual(
            errorResult('Certificate serial number must be non-zero'),
          );
        });
      });

      describe('Given certificate has negative serial number', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          const negativeSerial = new ArrayBuffer(8);
          const dataBytes = new Uint8Array(negativeSerial);
          dataBytes[0] = 0x80; // Set MSB to make it negative in ASN.1 INTEGER encoding
          dataBytes[1] = 0x01; // Add some value to make it non-zero
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2, // Valid version
              serialNumber: negativeSerial,
            },
          } as any);
          result = await validateLeafCertificate(validCert);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate serial number must be positive',
          });
        });

        it('Returns serial number negative error', () => {
          expect(result).toEqual(
            errorResult('Certificate serial number must be positive'),
          );
        });
      });
    });
  });

  describe('Given leaf certificate is valid', () => {
    beforeEach(async () => {
      const validCert = await createValidCertPem();
      const validSerial = new ArrayBuffer(8);
      const view = new Uint8Array(validSerial);
      view[0] = 0x01; // Positive number (MSB not set)
      view[1] = 0x23; // Some random bytes
      view[2] = 0x45;
      vi.spyOn(AsnConvert, 'parse').mockReturnValue({
        tbsCertificate: {
          version: 2, // Valid v3 certificate
          serialNumber: validSerial, // Valid serial number
        },
      } as any);
      result = await validateLeafCertificate(validCert);
    });

    it('Returns empty success', () => {
      expect(result).toEqual(emptySuccess());
    });
  });
});
