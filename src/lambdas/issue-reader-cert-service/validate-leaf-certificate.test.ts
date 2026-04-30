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
import {
  createValidCertPem,
  createValidSerialNumber,
} from '../../../tests/testUtils/create-valid-cert-pem.ts';
import { X509Certificate, Name } from '@peculiar/x509';
import { AsnConvert } from '@peculiar/asn1-schema';

const VALID_CERT_NAME =
  'C=GB, ST=London, L=London, O=Government Digital Service, CN=GOVUK Mobile Wallet GovVerifier CA';
const MOCK_CSR_SUBJECT_CN = 'Example Verifier Org';
const TWENTY_FOUR_HOURS_IN_MS = 24 * 60 * 60 * 1000;

describe('validateLeafCertificate', () => {
  let consoleErrorSpy: MockInstance;
  let result: Result<void, string>;

  const validSerial = createValidSerialNumber();

  const mockValidName = () => {
    const mockIssuerName = {
      getField: (field: string) => {
        const fields: Record<string, string[]> = {
          C: ['GB'],
          ST: ['London'],
          L: ['London'],
          O: ['Government Digital Service'],
          CN: ['GOVUK Mobile Wallet GovVerifier CA'],
        };
        return fields[field] ?? [];
      },
    } as unknown as Name;
    const mockSubjectName = {
      getField: (field: string) => {
        const fields: Record<string, string[]> = {
          C: ['GB'],
          ST: ['London'],
          L: ['London'],
          O: ['Government Digital Service'],
          CN: [MOCK_CSR_SUBJECT_CN],
        };
        return fields[field] ?? [];
      },
    } as unknown as Name;
    vi.spyOn(X509Certificate.prototype, 'issuerName', 'get').mockReturnValue(
      mockIssuerName,
    );
    vi.spyOn(X509Certificate.prototype, 'subjectName', 'get').mockReturnValue(
      mockSubjectName,
    );
  };

  const asnConvertParse = AsnConvert.parse.bind(AsnConvert);

  const mockAsnWithValidSerialAndSignature = (mockIssuerName = true) => {
    let callCount = 0;
    vi.spyOn(AsnConvert, 'parse').mockImplementation(
      (...args: Parameters<typeof AsnConvert.parse>) => {
        callCount++;
        if (callCount === 1) {
          // First call is from X509Certificate constructor - let it through
          return asnConvertParse(...args);
        }
        return {
          tbsCertificate: {
            version: 2,
            serialNumber: validSerial,
            signature: { algorithm: '1.2.840.10045.4.3.3' },
            issuer: {},
            subject: {},
          },
          signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.3' },
        } as ReturnType<typeof AsnConvert.parse>;
      },
    );
    if (mockIssuerName) mockValidName();
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
        result = await validateLeafCertificate(
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
        vi.spyOn(AsnConvert, 'parse').mockReturnValue({
          tbsCertificate: {
            version: 0, // v1 instead of v3 (2)
            serialNumber: new ArrayBuffer(9),
          },
        } as ReturnType<typeof AsnConvert.parse>);
        result = await validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
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
              version: 2,
              serialNumber: null,
            },
          } as ReturnType<typeof AsnConvert.parse>);
          result = await validateLeafCertificate(
            validCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
              version: 2,
              serialNumber: new ArrayBuffer(0),
            },
          } as ReturnType<typeof AsnConvert.parse>);
          result = await validateLeafCertificate(
            validCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2,
              serialNumber: new ArrayBuffer(21),
            },
          } as ReturnType<typeof AsnConvert.parse>);
          result = await validateLeafCertificate(
            validCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2,
              serialNumber: shortSerial,
            },
          } as ReturnType<typeof AsnConvert.parse>);
          result = await validateLeafCertificate(
            validCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2,
              serialNumber: new ArrayBuffer(9),
            },
          } as ReturnType<typeof AsnConvert.parse>);
          result = await validateLeafCertificate(
            validCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
          dataBytes[0] = 0x80; // Set MSB to make it negative in ASN.1 INTEGER encoding
          dataBytes[1] = 0x01;
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2,
              serialNumber: negativeSerial,
            },
          } as ReturnType<typeof AsnConvert.parse>);
          result = await validateLeafCertificate(
            validCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2,
              serialNumber: validSerial,
              signature: { algorithm: '1.2.840.10045.4.3.3' },
            },
            signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.2' },
          } as ReturnType<typeof AsnConvert.parse>);
          result = await validateLeafCertificate(
            validCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
          vi.spyOn(AsnConvert, 'parse').mockReturnValue({
            tbsCertificate: {
              version: 2,
              serialNumber: validSerial,
              signature: { algorithm: '1.2.840.10045.4.3.2' },
            },
            signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.2' },
          } as ReturnType<typeof AsnConvert.parse>);
          result = await validateLeafCertificate(
            validCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
            notBefore: new Date('2026-01-01T00:00:00Z'),
            notAfter: new Date('2026-01-02T00:00:00Z'),
          });
          mockAsnWithValidSerialAndSignature();
          result = await validateLeafCertificate(
            expiredCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
          mockAsnWithValidSerialAndSignature();
          result = await validateLeafCertificate(
            futureCert,
            MOCK_CSR_SUBJECT_CN,
          );
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

      describe('Given certificate validity period is not exactly 24 hours', () => {
        beforeEach(async () => {
          const notBefore = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago
          const invalidCert = await createValidCertPem({
            notBefore,
            notAfter: new Date(notBefore.getTime() + 26 * 60 * 60 * 1000), // 26 hours - outside 24-25 hour range
          });
          mockAsnWithValidSerialAndSignature();
          result = await validateLeafCertificate(
            invalidCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
          const notBefore = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago
          const invalidCert = await createValidCertPem({
            notBefore,
            notAfter: new Date(notBefore.getTime() + 2 * 60 * 60 * 1000), // 2 hours
          });
          mockAsnWithValidSerialAndSignature();
          result = await validateLeafCertificate(
            invalidCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
          const notBefore = new Date(Date.now() - 60 * 60 * 1000);
          const validCert = await createValidCertPem({
            name: VALID_CERT_NAME,
            notBefore,
            notAfter: new Date(notBefore.getTime() + TWENTY_FOUR_HOURS_IN_MS),
          });
          mockAsnWithValidSerialAndSignature();
          vi.spyOn(
            X509Certificate.prototype,
            'issuerName',
            'get',
          ).mockReturnValue({
            getField: () => ['Wrong Issuer CN'],
          } as unknown as Name);
          result = await validateLeafCertificate(
            validCert,
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
          const notBefore = new Date(Date.now() - 60 * 60 * 1000);
          const wrongNameCert = await createValidCertPem({
            name: 'C=US, ST=London, L=London, O=Government Digital Service, CN=GOVUK Mobile Wallet GovVerifier CA',
            notBefore,
            notAfter: new Date(notBefore.getTime() + TWENTY_FOUR_HOURS_IN_MS),
          });
          mockAsnWithValidSerialAndSignature();
          vi.spyOn(
            X509Certificate.prototype,
            'issuerName',
            'get',
          ).mockReturnValue({
            getField: (field: string) => {
              const fields: Record<string, string[]> = {
                C: ['US'],
                ST: ['London'],
                L: ['London'],
                O: ['Government Digital Service'],
                CN: ['GOVUK Mobile Wallet GovVerifier CA'],
              };
              return fields[field] ?? [];
            },
          } as unknown as Name);
          result = await validateLeafCertificate(
            wrongNameCert,
            MOCK_CSR_SUBJECT_CN,
          );
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
          const notBefore = new Date(Date.now() - 60 * 60 * 1000);
          const validCert = await createValidCertPem({
            name: VALID_CERT_NAME,
            notBefore,
            notAfter: new Date(notBefore.getTime() + TWENTY_FOUR_HOURS_IN_MS),
          });
          mockAsnWithValidSerialAndSignature();
          result = await validateLeafCertificate(validCert, 'Wrong CN');
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
          const notBefore = new Date(Date.now() - 60 * 60 * 1000);
          const validCert = await createValidCertPem({
            name: VALID_CERT_NAME,
            notBefore,
            notAfter: new Date(notBefore.getTime() + TWENTY_FOUR_HOURS_IN_MS),
          });
          mockAsnWithValidSerialAndSignature();
          vi.spyOn(
            X509Certificate.prototype,
            'subjectName',
            'get',
          ).mockReturnValue({
            getField: (field: string) => {
              const fields: Record<string, string[]> = {
                C: ['US'],
                ST: ['London'],
                L: ['London'],
                O: ['Government Digital Service'],
                CN: [MOCK_CSR_SUBJECT_CN],
              };
              return fields[field] ?? [];
            },
          } as unknown as Name);
          result = await validateLeafCertificate(
            validCert,
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
      const notBefore = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago
      const validCert = await createValidCertPem({
        name: VALID_CERT_NAME,
        notBefore,
        notAfter: new Date(notBefore.getTime() + TWENTY_FOUR_HOURS_IN_MS),
      });
      mockAsnWithValidSerialAndSignature();
      result = await validateLeafCertificate(validCert, MOCK_CSR_SUBJECT_CN);
    });

    it('Returns empty success', () => {
      expect(result).toEqual(emptySuccess());
    });
  });
});
