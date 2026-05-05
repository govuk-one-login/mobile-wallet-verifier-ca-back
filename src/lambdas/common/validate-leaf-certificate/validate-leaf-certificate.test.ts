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
import '../../../../tests/testUtils/matchers.ts';
import { emptySuccess, errorResult, Result } from '../result/result.ts';
import { createValidCertPem } from '../../../../tests/testUtils/create-valid-cert-pem.ts';
import { AsnConvert } from '@peculiar/asn1-schema';
import {
  TWENTY_FOUR_HOURS_IN_MS,
  EXPECTED_ISSUER_AND_SUBJECT_NAME,
  EXPECTED_ISSUER_CN,
} from '../certificate-service-constants/certificate-service-constants.ts';

const VALID_ISSUER_NAME = `C=${EXPECTED_ISSUER_AND_SUBJECT_NAME.C}, ST=${EXPECTED_ISSUER_AND_SUBJECT_NAME.ST}, L=${EXPECTED_ISSUER_AND_SUBJECT_NAME.L}, O=${EXPECTED_ISSUER_AND_SUBJECT_NAME.O}, CN=${EXPECTED_ISSUER_CN}`;
const MOCK_CSR_SUBJECT_CN = 'Example Verifier Org';

describe('validateLeafCertificate', () => {
  let consoleErrorSpy: MockInstance;
  let result: Result<void, string>;

  // AsnConvert.parse is called once by the X509Certificate constructor, then again
  // by our certAsn() helper for each validation. We let the first call through so
  // the constructor succeeds, then return a stub for subsequent calls so we can
  // exercise specific validation branches that can't be produced via the cert generator.
  const asnConvertParse = AsnConvert.parse.bind(AsnConvert);
  const mockAsnAfterConstructor = (
    stub: ReturnType<typeof AsnConvert.parse>,
  ) => {
    let callCount = 0;
    vi.spyOn(AsnConvert, 'parse').mockImplementation(
      (...args: Parameters<typeof AsnConvert.parse>) => {
        callCount++;
        if (callCount === 1) return asnConvertParse(...args);
        return stub;
      },
    );
  };

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
        result = validateLeafCertificate(
          await createValidCertPem({ invalidX509: true }),
          MOCK_CSR_SUBJECT_CN,
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
        mockAsnAfterConstructor({
          tbsCertificate: {
            version: 0, // v1 instead of v3 (2)
            serialNumber: new ArrayBuffer(9),
          },
        } as ReturnType<typeof AsnConvert.parse>);
        result = validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
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
          mockAsnAfterConstructor({
            tbsCertificate: { version: 2, serialNumber: null },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
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
          mockAsnAfterConstructor({
            tbsCertificate: { version: 2, serialNumber: new ArrayBuffer(0) },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
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
          mockAsnAfterConstructor({
            tbsCertificate: { version: 2, serialNumber: new ArrayBuffer(21) },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate serial number must be between 9 and 20 bytes',
          });
        });

        it('Returns serial number length error', () => {
          expect(result).toEqual(
            errorResult(
              'Certificate serial number must be between 9 and 20 bytes',
            ),
          );
        });
      });

      describe('Given certificate serial number is shorter than 9 bytes', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          const shortSerial = new ArrayBuffer(8);
          new Uint8Array(shortSerial)[0] = 0x01;
          mockAsnAfterConstructor({
            tbsCertificate: { version: 2, serialNumber: shortSerial },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate serial number must be between 9 and 20 bytes',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult(
              'Certificate serial number must be between 9 and 20 bytes',
            ),
          );
        });
      });

      describe('Given certificate has zero serial number', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          mockAsnAfterConstructor({
            tbsCertificate: { version: 2, serialNumber: new ArrayBuffer(9) },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
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
          const negativeSerial = new ArrayBuffer(9);
          const dataBytes = new Uint8Array(negativeSerial);
          dataBytes[0] = 0x80; // MSB set = negative in ASN.1 INTEGER encoding
          dataBytes[1] = 0x01;
          mockAsnAfterConstructor({
            tbsCertificate: { version: 2, serialNumber: negativeSerial },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
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

    describe('Given certificate signature algorithm validation fails', () => {
      describe('Given TBS and outer signature algorithm OIDs do not match', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          const validSerial = new ArrayBuffer(16);
          new Uint8Array(validSerial)[0] = 0x01;
          mockAsnAfterConstructor({
            tbsCertificate: {
              version: 2,
              serialNumber: validSerial,
              signature: { algorithm: '1.2.840.10045.4.3.3' },
            },
            signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.2' },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate signature algorithm OID mismatch between TBS and outer certificate',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult(
              'Certificate signature algorithm OID mismatch between TBS and outer certificate',
            ),
          );
        });
      });

      describe('Given signature algorithm OID is not the expected ECDSA with SHA-384', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          const validSerial = new ArrayBuffer(16);
          new Uint8Array(validSerial)[0] = 0x01;
          mockAsnAfterConstructor({
            tbsCertificate: {
              version: 2,
              serialNumber: validSerial,
              signature: { algorithm: '1.2.840.10045.4.3.2' },
            },
            signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.2' },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate signature algorithm must be ECDSA with SHA-384 on P-384',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult(
              'Certificate signature algorithm must be ECDSA with SHA-384 on P-384',
            ),
          );
        });
      });
    });

    describe('Given certificate validity validation fails', () => {
      describe('Given certificate is expired', () => {
        beforeEach(async () => {
          const expiredCert = await createValidCertPem({
            notBefore: new Date(Date.now() - 48 * 60 * 60 * 1000),
            notAfter: new Date(Date.now() - 24 * 60 * 60 * 1000),
          });
          result = validateLeafCertificate(expiredCert, MOCK_CSR_SUBJECT_CN);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate is not within its validity period',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult('Certificate is not within its validity period'),
          );
        });
      });

      describe('Given certificate is not yet valid', () => {
        beforeEach(async () => {
          const futureDate = new Date(Date.now() + 48 * 60 * 60 * 1000);
          const futureCert = await createValidCertPem({
            notBefore: futureDate,
            notAfter: new Date(futureDate.getTime() + TWENTY_FOUR_HOURS_IN_MS),
          });
          result = validateLeafCertificate(futureCert, MOCK_CSR_SUBJECT_CN);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate is not within its validity period',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult('Certificate is not within its validity period'),
          );
        });
      });

      describe('Given certificate validity period is greater than 25 hours', () => {
        beforeEach(async () => {
          const notBefore = new Date(Date.now() - 60 * 60 * 1000);
          const invalidCert = await createValidCertPem({
            notBefore,
            notAfter: new Date(notBefore.getTime() + 26 * 60 * 60 * 1000),
          });
          result = validateLeafCertificate(invalidCert, MOCK_CSR_SUBJECT_CN);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate validity period must be between 24 and 25 hours',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult(
              'Certificate validity period must be between 24 and 25 hours',
            ),
          );
        });
      });

      describe('Given certificate validity period is less than 24 hours', () => {
        beforeEach(async () => {
          const notBefore = new Date(Date.now() - 60 * 60 * 1000);
          const invalidCert = await createValidCertPem({
            notBefore,
            notAfter: new Date(notBefore.getTime() + 2 * 60 * 60 * 1000),
          });
          result = validateLeafCertificate(invalidCert, MOCK_CSR_SUBJECT_CN);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate validity period must be between 24 and 25 hours',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult(
              'Certificate validity period must be between 24 and 25 hours',
            ),
          );
        });
      });
    });

    describe('Given certificate issuer validation fails', () => {
      describe('Given issuer CN does not match expected value', () => {
        beforeEach(async () => {
          const wrongIssuerCert = await createValidCertPem({
            issuerName: `C=GB, ST=London, L=London, O=Government Digital Service, CN=Wrong Issuer CN`,
          });
          result = validateLeafCertificate(
            wrongIssuerCert,
            MOCK_CSR_SUBJECT_CN,
          );
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate issuer Common name must match expected name value',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult(
              'Certificate issuer Common name must match expected name value',
            ),
          );
        });
      });

      describe('Given issuer name fields do not match expected values', () => {
        beforeEach(async () => {
          const wrongNameCert = await createValidCertPem({
            issuerName: `C=US, ST=London, L=London, O=Government Digital Service, CN=${EXPECTED_ISSUER_CN}`,
          });
          result = validateLeafCertificate(wrongNameCert, MOCK_CSR_SUBJECT_CN);
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate issuer must match expected name values',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult('Certificate issuer must match expected name values'),
          );
        });
      });
    });

    describe('Given certificate subject validation fails', () => {
      describe('Given subject CN does not match CSR subject CN', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem({
            issuerName: VALID_ISSUER_NAME,
          });
          result = validateLeafCertificate(validCert, 'Wrong CN');
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate subject CN does not match CSR subject CN',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult('Certificate subject CN does not match CSR subject CN'),
          );
        });
      });

      describe('Given subject name fields do not match expected values', () => {
        beforeEach(async () => {
          const wrongSubjectCert = await createValidCertPem({
            issuerName: VALID_ISSUER_NAME,
            subjectName: `C=US, ST=London, L=London, O=Government Digital Service, CN=${MOCK_CSR_SUBJECT_CN}`,
          });
          result = validateLeafCertificate(
            wrongSubjectCert,
            MOCK_CSR_SUBJECT_CN,
          );
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate subject must match expected name values',
          });
        });

        it('Returns an error result', () => {
          expect(result).toEqual(
            errorResult('Certificate subject must match expected name values'),
          );
        });
      });
    });
  });

  describe('Given leaf certificate is valid', () => {
    beforeEach(async () => {
      const validCert = await createValidCertPem({
        issuerName: VALID_ISSUER_NAME,
        subjectCn: MOCK_CSR_SUBJECT_CN,
      });
      result = validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
    });

    it('Returns empty success', () => {
      expect(result).toEqual(emptySuccess());
    });
  });
});
