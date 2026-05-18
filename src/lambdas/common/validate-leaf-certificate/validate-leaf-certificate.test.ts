import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  afterEach,
  MockInstance,
} from 'vitest';
import { X509Certificate } from '@peculiar/x509';
import { validateLeafCertificate } from './validate-leaf-certificate.ts';
import '../../../../tests/testUtils/matchers.ts';
import { emptyFailure, emptySuccess, Result } from '../result/result.ts';
import {
  createValidCertPem,
  createCaAndLeafCertPem,
} from '../../../../tests/testUtils/create-valid-cert-pem.ts';
import { AsnConvert } from '@peculiar/asn1-schema';
import {
  AuthorityKeyIdentifier,
  SubjectKeyIdentifier,
  KeyUsage,
  ExtendedKeyUsage,
  id_ce_subjectKeyIdentifier,
  id_ce_keyUsage,
  id_ce_extKeyUsage,
  id_ce_authorityKeyIdentifier,
} from '@peculiar/asn1-x509';
import { TWENTY_FOUR_HOURS_IN_MS } from '../certificate-service-constants/certificate-service-constants.ts';

const MOCK_CSR_SUBJECT_CN = 'Example Verifier Org';

describe('validateLeafCertificate', () => {
  let consoleErrorSpy: MockInstance;
  let result: Result<void, void>;
  let mockCertificateChain: string;

  // AsnConvert.parse is called once by the X509Certificate constructor, then again
  // by our certAsn() helper for each validation. We let the first call through so
  // the constructor succeeds, then return a stub for subsequent calls so we can
  // exercise specific validation branches that can't be produced via the cert generator.
  const asnConvertParse = AsnConvert.parse.bind(AsnConvert);
  const mockAsnAfterConstructor = (
    stub: ReturnType<typeof AsnConvert.parse>,
    letThroughCount = 8,
  ) => {
    let callCount = 0;
    vi.spyOn(AsnConvert, 'parse').mockImplementation(
      (...args: Parameters<typeof AsnConvert.parse>) => {
        callCount++;
        if (callCount <= letThroughCount) return asnConvertParse(...args);
        return stub;
      },
    );
  };

  const mockAsnThrowAfterNCalls = (n: number) => {
    let callCount = 0;
    vi.spyOn(AsnConvert, 'parse').mockImplementation(
      (...args: Parameters<typeof AsnConvert.parse>) => {
        callCount++;
        if (callCount <= n) return asnConvertParse(...args);
        throw new Error('Mocked parse error');
      },
    );
  };

  beforeEach(async () => {
    consoleErrorSpy = vi.spyOn(console, 'error');
    vi.clearAllMocks();
    if (!mockCertificateChain) {
      ({ caCertPem: mockCertificateChain } =
        await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN));
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Given Leaf certificate verification fails', () => {
    describe('Given certificate is not valid X.509 format', () => {
      beforeEach(async () => {
        result = validateLeafCertificate({
          certPem: await createValidCertPem({ invalidX509: true }),
          csrSubjectCn: MOCK_CSR_SUBJECT_CN,
          certificateChain: mockCertificateChain,
        });
      });

      it('Logs error', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode:
            'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
          errorMessage: 'Certificate not valid X.509 format',
        });
      });

      it('Returns an empty failure', () => {
        expect(result).toEqual(emptyFailure());
      });
    });

    describe('Given certificate version validation fails', () => {
      describe('Given certificate version parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          mockAsnAfterConstructor(
            null as ReturnType<typeof AsnConvert.parse>,
            1,
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse certificate version',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate version is not v3', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          mockAsnAfterConstructor(
            {
              tbsCertificate: {
                version: 0, // v1 instead of v3 (2)
                serialNumber: new ArrayBuffer(9),
              },
            } as ReturnType<typeof AsnConvert.parse>,
            1,
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate version must be v3',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given certificate serial number validation fails', () => {
      describe('Given certificate serial number parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          mockAsnThrowAfterNCalls(2);
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse certificate serial number',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate has missing serial number', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          mockAsnAfterConstructor(
            {
              tbsCertificate: { version: 2, serialNumber: null },
            } as ReturnType<typeof AsnConvert.parse>,
            2,
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate serial number must be present',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate has empty serial number', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          mockAsnAfterConstructor(
            {
              tbsCertificate: { version: 2, serialNumber: new ArrayBuffer(0) },
            } as ReturnType<typeof AsnConvert.parse>,
            2,
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate serial number must be present',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate has serial number exceeding 20 octets', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          mockAsnAfterConstructor(
            {
              tbsCertificate: { version: 2, serialNumber: new ArrayBuffer(21) },
            } as ReturnType<typeof AsnConvert.parse>,
            2,
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate serial number must be between 9 and 20 bytes',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate serial number is shorter than 9 bytes', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          const shortSerial = new ArrayBuffer(8);
          new Uint8Array(shortSerial)[0] = 0x01;
          mockAsnAfterConstructor(
            {
              tbsCertificate: { version: 2, serialNumber: shortSerial },
            } as ReturnType<typeof AsnConvert.parse>,
            2,
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate serial number must be between 9 and 20 bytes',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate has zero serial number', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          mockAsnAfterConstructor(
            {
              tbsCertificate: { version: 2, serialNumber: new ArrayBuffer(9) },
            } as ReturnType<typeof AsnConvert.parse>,
            2,
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate serial number must be non-zero',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate has negative serial number', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          const negativeSerial = new ArrayBuffer(9);
          const dataBytes = new Uint8Array(negativeSerial);
          dataBytes[0] = 0x80; // MSB set = negative in ASN.1 INTEGER encoding
          dataBytes[1] = 0x01;
          mockAsnAfterConstructor(
            {
              tbsCertificate: { version: 2, serialNumber: negativeSerial },
            } as ReturnType<typeof AsnConvert.parse>,
            2,
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate serial number must be positive',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given certificate signature algorithm validation fails', () => {
      describe('Given certificate signature algorithm parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          mockAsnThrowAfterNCalls(3);
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse certificate signature algorithm',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given TBS and outer signature algorithm OIDs do not match', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          const validSerial = new ArrayBuffer(16);
          new Uint8Array(validSerial)[0] = 0x01;
          mockAsnAfterConstructor(
            {
              tbsCertificate: {
                version: 2,
                serialNumber: validSerial,
                signature: { algorithm: '1.2.840.10045.4.3.3' },
              },
              signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.2' },
            } as ReturnType<typeof AsnConvert.parse>,
            3,
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate signature algorithm OID mismatch between TBS and outer certificate',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given signature algorithm OID is not the expected ECDSA with SHA-384', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          const validSerial = new ArrayBuffer(16);
          new Uint8Array(validSerial)[0] = 0x01;
          mockAsnAfterConstructor(
            {
              tbsCertificate: {
                version: 2,
                serialNumber: validSerial,
                signature: { algorithm: '1.2.840.10045.4.3.2' },
              },
              signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.2' },
            } as ReturnType<typeof AsnConvert.parse>,
            3,
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate signature algorithm must be ECDSA with SHA-384 on P-384',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given certificate validity validation fails', () => {
      describe('Given certificate validity parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          vi.spyOn(
            X509Certificate.prototype,
            'notBefore',
            'get',
          ).mockImplementation(() => {
            throw new Error('Mocked notBefore error');
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse certificate validity',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate is expired', () => {
        beforeEach(async () => {
          const notBefore = new Date(Date.now() - 48 * 60 * 60 * 1000);
          const { caCertPem, leafCertPem } = await createCaAndLeafCertPem(
            MOCK_CSR_SUBJECT_CN,
            {
              notBefore,
              notAfter: new Date(Date.now() - 24 * 60 * 60 * 1000),
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate is not within its validity period',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate is not yet valid', () => {
        beforeEach(async () => {
          const futureDate = new Date(Date.now() + 48 * 60 * 60 * 1000);
          const { caCertPem, leafCertPem } = await createCaAndLeafCertPem(
            MOCK_CSR_SUBJECT_CN,
            {
              notBefore: futureDate,
              notAfter: new Date(
                futureDate.getTime() + TWENTY_FOUR_HOURS_IN_MS,
              ),
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate is not within its validity period',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate validity period is greater than 25 hours', () => {
        beforeEach(async () => {
          const notBefore = new Date(Date.now() - 60 * 60 * 1000);
          const { caCertPem, leafCertPem } = await createCaAndLeafCertPem(
            MOCK_CSR_SUBJECT_CN,
            {
              notBefore,
              notAfter: new Date(notBefore.getTime() + 26 * 60 * 60 * 1000),
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate validity period must be between 24 and 25 hours',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate validity period is less than 24 hours', () => {
        beforeEach(async () => {
          const notBefore = new Date(Date.now() - 60 * 60 * 1000);
          const { caCertPem, leafCertPem } = await createCaAndLeafCertPem(
            MOCK_CSR_SUBJECT_CN,
            {
              notBefore,
              notAfter: new Date(notBefore.getTime() + 2 * 60 * 60 * 1000),
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate validity period must be between 24 and 25 hours',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given certificate issuer validation fails', () => {
      describe('Given certificate issuer parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const validCert = await createValidCertPem();
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              const parsed = asnConvertParse(...args);
              if (
                parsed &&
                typeof parsed === 'object' &&
                'tbsCertificate' in parsed
              ) {
                Object.defineProperty(parsed.tbsCertificate, 'issuer', {
                  get() {
                    throw new Error('Mocked issuer error');
                  },
                });
              }
              return parsed;
            },
          );
          result = validateLeafCertificate({
            certPem: validCert,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: mockCertificateChain,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse certificate issuer',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given leaf certificate issuer does not match CA certificate subject', () => {
        beforeEach(async () => {
          const { leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          // Generate a CA with a different subject name so the binary comparison fails
          const differentCaCertPem = await createValidCertPem({
            subjectCn: 'Different CA',
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: differentCaCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate issuer does not match CA certificate subject',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given certificate subject validation fails', () => {
      describe('Given certificate subject parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          vi.spyOn(
            X509Certificate.prototype,
            'subjectName',
            'get',
          ).mockImplementation(() => {
            throw new Error('Mocked subjectName error');
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse certificate subject',
          });
        });

        it('Returns a empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given subject CN does not match CSR subject CN', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: 'Wrong CN',
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate subject CN does not match CSR subject CN',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given subject name fields C do not match expected values', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } = await createCaAndLeafCertPem(
            MOCK_CSR_SUBJECT_CN,
            {
              subjectName: `C=US, ST=London, L=London, O=Government Digital Service, CN=${MOCK_CSR_SUBJECT_CN}`,
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate subject must match expected name values',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given certificate subject public key info validation fails', () => {
      describe('Given subject public key info parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          mockAsnThrowAfterNCalls(8);
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse certificate subject public key info',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate public key algorithm is not ECDSA', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const validSerial = new ArrayBuffer(16);
          new Uint8Array(validSerial)[0] = 0x01;
          mockAsnAfterConstructor({
            tbsCertificate: {
              version: 2,
              serialNumber: validSerial,
              signature: { algorithm: '1.2.840.10045.4.3.3' },
              subjectPublicKeyInfo: {
                algorithm: {
                  algorithm: '1.2.840.113549.1.1.1',
                  parameters: null,
                },
                subjectPublicKey: new ArrayBuffer(97),
              },
            },
            signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.3' },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate public key algorithm must be ECDSA',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate public key curve parameters are missing', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const validSerial = new ArrayBuffer(16);
          new Uint8Array(validSerial)[0] = 0x01;
          mockAsnAfterConstructor({
            tbsCertificate: {
              version: 2,
              serialNumber: validSerial,
              signature: { algorithm: '1.2.840.10045.4.3.3' },
              subjectPublicKeyInfo: {
                algorithm: {
                  algorithm: '1.2.840.10045.2.1',
                  parameters: null,
                },
                subjectPublicKey: new ArrayBuffer(97),
              },
            },
            signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.3' },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate public key curve parameters must be present',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate public key curve is not P-384', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const validSerial = new ArrayBuffer(16);
          new Uint8Array(validSerial)[0] = 0x01;
          // DER encoding of OID 1.2.840.10045.3.1.7 (P-256)
          const p256Params = new Uint8Array([
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
          ]).buffer;
          mockAsnAfterConstructor({
            tbsCertificate: {
              version: 2,
              serialNumber: validSerial,
              signature: { algorithm: '1.2.840.10045.4.3.3' },
              subjectPublicKeyInfo: {
                algorithm: {
                  algorithm: '1.2.840.10045.2.1',
                  parameters: p256Params,
                },
                subjectPublicKey: new ArrayBuffer(65),
              },
            },
            signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.3' },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate public key curve must be P-384 only',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate subject public key is empty', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const validSerial = new ArrayBuffer(16);
          new Uint8Array(validSerial)[0] = 0x01;
          const p384Params = new Uint8Array([
            0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
          ]).buffer;
          mockAsnAfterConstructor({
            tbsCertificate: {
              version: 2,
              serialNumber: validSerial,
              signature: { algorithm: '1.2.840.10045.4.3.3' },
              subjectPublicKeyInfo: {
                algorithm: {
                  algorithm: '1.2.840.10045.2.1',
                  parameters: p384Params,
                },
                subjectPublicKey: new ArrayBuffer(0),
              },
            },
            signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.3' },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate public key must be present',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate public key is not in uncompressed form', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const validSerial = new ArrayBuffer(16);
          new Uint8Array(validSerial)[0] = 0x01;
          const p384Params = new Uint8Array([
            0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
          ]).buffer;
          const compressedPublicKey = new Uint8Array(49).fill(0);
          compressedPublicKey[0] = 0x02;
          mockAsnAfterConstructor({
            tbsCertificate: {
              version: 2,
              serialNumber: validSerial,
              signature: { algorithm: '1.2.840.10045.4.3.3' },
              subjectPublicKeyInfo: {
                algorithm: {
                  algorithm: '1.2.840.10045.2.1',
                  parameters: p384Params,
                },
                subjectPublicKey: compressedPublicKey.buffer,
              },
            },
            signatureAlgorithm: { algorithm: '1.2.840.10045.4.3.3' },
          } as ReturnType<typeof AsnConvert.parse>);
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate public key must be in uncompressed form (0x04 prefix)',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given SubjectPublicKeyInfo serialization throws unexpectedly', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realSerialize = AsnConvert.serialize.bind(AsnConvert);
          let serializeCallCount = 0;
          vi.spyOn(AsnConvert, 'serialize').mockImplementation(
            (...args: Parameters<typeof AsnConvert.serialize>) => {
              serializeCallCount++;
              // First 2 calls are from validateIssuer binary comparison (leaf issuer + CA subject)
              if (serializeCallCount <= 2) return realSerialize(...args);
              throw new Error('Mocked serialize error');
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to serialize SubjectPublicKeyInfo',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given SubjectPublicKeyInfo length is not 120 bytes', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realSerialize = AsnConvert.serialize.bind(AsnConvert);
          let serializeCallCount = 0;
          vi.spyOn(AsnConvert, 'serialize').mockImplementation(
            (...args: Parameters<typeof AsnConvert.serialize>) => {
              serializeCallCount++;
              // First 2 calls are from validateIssuer binary comparison (leaf issuer + CA subject)
              if (serializeCallCount <= 2) return realSerialize(...args);
              return new ArrayBuffer(100);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Certificate SubjectPublicKeyInfo must be 120 bytes for P-384',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given extractCaSubjectKeyIdentifier fails', () => {
      describe('Given CA certificate is not valid X.509 format', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          // Mock AsnConvert.parse to throw when parsing the CA cert inside extractCaSubjectKeyIdentifier
          // (after validateIssuer's certAsn calls have already succeeded)
          let parseCallCount = 0;
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              parseCallCount++;
              // Let through all calls up to and including validateIssuer's certAsn(caCert),
              // then throw to simulate an invalid CA cert in extractCaSubjectKeyIdentifier
              if (parseCallCount <= 9) return asnConvertParse(...args);
              throw new Error('Mocked invalid CA cert');
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'CA certificate is not valid X.509 format',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given CA certificate is missing Subject Key Identifier extension', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } = await createCaAndLeafCertPem(
            MOCK_CSR_SUBJECT_CN,
            { caWithoutSki: true },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Failed to extract Subject Key Identifier from CA certificate',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given CA Subject Key Identifier extension parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          let skiCallCount = 0;
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              if (args[1] === SubjectKeyIdentifier) {
                skiCallCount++;
                if (skiCallCount === 2)
                  throw new Error('Mocked SKI parse error');
              }
              return asnConvertParse(...args);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Failed to parse Subject Key Identifier from CA certificate',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given authority key identifier validation fails', () => {
      describe('Given certificate extensions getter throws during AKI lookup', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          let callCount = 0;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            callCount++;
            // First call: CA cert SKI lookup — let through
            if (callCount <= 1) return realExtensionsGetter.call(this);
            // Second call: leaf cert AKI lookup via findExtension — throw
            throw new Error('Mocked extensions error');
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse certificate extensions',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given AKI extension is missing from leaf certificate', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          let callCount = 0;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            callCount++;
            // First call: CA cert SKI lookup — let through
            if (callCount <= 1) return realExtensionsGetter.call(this);
            // Second call: Leaf cert AKI lookup — return empty
            return [];
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Authority Key Identifier extension must be present',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given AKI extension parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          let akiParseCount = 0;
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              if (args[1] === AuthorityKeyIdentifier) {
                akiParseCount++;
                // First call is during CA cert construction; second is our validation
                if (akiParseCount > 1)
                  throw new Error('Mocked AKI parse error');
              }
              return asnConvertParse(...args);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse Authority Key Identifier extension',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given AKI extension is missing keyIdentifier field', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              if (args[1] === AuthorityKeyIdentifier) {
                return new AuthorityKeyIdentifier();
              }
              return asnConvertParse(...args);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Authority Key Identifier must contain keyIdentifier field',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given AKI key ID does not match CA subject key ID', () => {
        beforeEach(async () => {
          const { leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const differentCaCertPem = (
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN)
          ).caCertPem;
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: differentCaCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Authority Key Identifier does not match expected CA key identifier',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given AKI extension is marked critical', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            return realExtensionsGetter
              .call(this)
              .map((ext: { type: string; critical: boolean }) =>
                ext.type === id_ce_authorityKeyIdentifier
                  ? { ...ext, critical: true }
                  : ext,
              );
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Extension must be non-critical',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given subject key identifier validation fails', () => {
      describe('Given SKI extension is missing from leaf certificate', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          let callCount = 0;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            callCount++;
            if (callCount === 3) {
              // Third call is leaf cert SKI lookup — return extensions without SKI
              const exts = realExtensionsGetter.call(this);
              return exts.filter(
                (ext: { type: string }) =>
                  ext.type !== id_ce_subjectKeyIdentifier,
              );
            }
            return realExtensionsGetter.call(this);
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Subject Key Identifier extension must be present',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given SKI extension parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          let skiCallCount = 0;
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              if (args[1] === SubjectKeyIdentifier) {
                skiCallCount++;
                // Earlier calls are from CA cert construction/extractCaSubjectKeyIdentifier;
                // the last call is our explicit parse in validateSubjectKeyIdentifier
                if (skiCallCount === 4) {
                  throw new Error('Mocked SKI parse error');
                }
              }
              return asnConvertParse(...args);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse Subject Key Identifier extension',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given SubjectPublicKeyInfo parsing throws during SKI validation', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          let skiParseCount = 0;
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              const result = asnConvertParse(...args);
              if (args[1] === SubjectKeyIdentifier) {
                skiParseCount++;
                // After the leaf cert's SKI extension is parsed (4th SubjectKeyIdentifier parse),
                // the next certAsn call is in validateSubjectKeyIdentifier for SPKI.
                // We override tbsCertificate to throw on subjectPublicKeyInfo access.
                if (skiParseCount === 4) {
                  vi.spyOn(AsnConvert, 'parse').mockImplementation(() => {
                    throw new Error('Mocked certAsn error in SKI validation');
                  });
                }
              }
              return result;
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Failed to parse SubjectPublicKeyInfo for Subject Key Identifier validation',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given SKI does not match SHA-1 hash of public key', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          let callCount = 0;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            callCount++;
            const exts = realExtensionsGetter.call(this);
            if (callCount === 3) {
              // Third extensions access is for leaf cert SKI validation
              // Replace the SKI extension value with a fake one
              return exts.map(
                (ext: {
                  type: string;
                  value: ArrayBuffer;
                  critical: boolean;
                }) => {
                  if (ext.type === id_ce_subjectKeyIdentifier) {
                    const fakeSki = new SubjectKeyIdentifier(
                      new Uint8Array(20).fill(0xff).buffer,
                    );
                    return {
                      ...ext,
                      value: AsnConvert.serialize(fakeSki),
                    };
                  }
                  return ext;
                },
              );
            }
            return exts;
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Subject Key Identifier does not match SHA-1 hash of public key',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given SKI extension is marked critical', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            return realExtensionsGetter
              .call(this)
              .map((ext: { type: string; critical: boolean }) =>
                ext.type === id_ce_subjectKeyIdentifier
                  ? { ...ext, critical: true }
                  : ext,
              );
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Extension must be non-critical',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given key usage validation fails', () => {
      describe('Given Key Usage extension is missing from leaf certificate', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          let callCount = 0;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            callCount++;
            if (callCount === 4) {
              // Fourth call is validateKeyUsage — return extensions without Key Usage
              const exts = realExtensionsGetter.call(this);
              return exts.filter(
                (ext: { type: string }) => ext.type !== id_ce_keyUsage,
              );
            }
            return realExtensionsGetter.call(this);
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Key Usage extension must be present',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given Key Usage extension parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          let kuCallCount = 0;
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              if (args[1] === KeyUsage) {
                kuCallCount++;
                // First call is from the extensions getter internally;
                // second call is our explicit parse in validateKeyUsage
                if (kuCallCount === 2) {
                  throw new Error('Mocked KeyUsage parse error');
                }
              }
              return asnConvertParse(...args);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse Key Usage extension',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given Key Usage contains more than just Digital Signature', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              if (args[1] === KeyUsage) {
                // Return a KeyUsage with digitalSignature + keyEncipherment (1 + 4 = 5)
                return new KeyUsage(new Uint8Array([0b10100000]).buffer);
              }
              return asnConvertParse(...args);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Key Usage must contain only Digital Signature',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given Key Usage does not contain Digital Signature', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              if (args[1] === KeyUsage) {
                // Return a KeyUsage with only keyEncipherment (bit 2)
                return new KeyUsage(new Uint8Array([0b00100000]).buffer);
              }
              return asnConvertParse(...args);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Key Usage must contain only Digital Signature',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given Key Usage extension is marked non-critical', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            return realExtensionsGetter
              .call(this)
              .map((ext: { type: string; critical: boolean }) =>
                ext.type === id_ce_keyUsage ? { ...ext, critical: false } : ext,
              );
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Extension must be critical',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given extended key usage validation fails', () => {
      describe('Given EKU extension is missing from leaf certificate', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          let callCount = 0;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            callCount++;
            if (callCount === 5) {
              // Fifth call is validateExtendedKeyUsage — return extensions without EKU
              const exts = realExtensionsGetter.call(this);
              return exts.filter(
                (ext: { type: string }) => ext.type !== id_ce_extKeyUsage,
              );
            }
            return realExtensionsGetter.call(this);
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Extended Key Usage extension must be present',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given EKU extension parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          let ekuCallCount = 0;
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              if (args[1] === ExtendedKeyUsage) {
                ekuCallCount++;
                // First call is from the extensions getter internally;
                // second call is our explicit parse in validateExtendedKeyUsage
                if (ekuCallCount === 2) {
                  throw new Error('Mocked EKU parse error');
                }
              }
              return asnConvertParse(...args);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse Extended Key Usage extension',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given EKU contains an unexpected OID', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          let ekuCallCount = 0;
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              if (args[1] === ExtendedKeyUsage) {
                ekuCallCount++;
                if (ekuCallCount === 2) {
                  return new ExtendedKeyUsage(['1.3.6.1.5.5.7.3.1']);
                }
              }
              return asnConvertParse(...args);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Extended Key Usage must contain only the expected OIDs',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given EKU contains extra OIDs alongside the expected one', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          let ekuCallCount = 0;
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              if (args[1] === ExtendedKeyUsage) {
                ekuCallCount++;
                if (ekuCallCount === 2) {
                  return new ExtendedKeyUsage([
                    '1.0.18013.5.1.6',
                    '1.3.6.1.5.5.7.3.1',
                  ]);
                }
              }
              return asnConvertParse(...args);
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage:
              'Extended Key Usage must contain only the expected OIDs',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given EKU extension is marked non-critical', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            return realExtensionsGetter
              .call(this)
              .map((ext: { type: string; critical: boolean }) =>
                ext.type === id_ce_extKeyUsage
                  ? { ...ext, critical: false }
                  : ext,
              );
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Extension must be critical',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given no unknown critical extensions validation fails', () => {
      describe('Given certificate extensions getter throws during unknown critical extension check', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          let callCount = 0;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            callCount++;
            // Calls 1-5: CA SKI, leaf AKI, leaf SKI, leaf KU, leaf EKU — let through
            if (callCount <= 5) return realExtensionsGetter.call(this);
            // Call 6: validateNoUnknownCriticalExtensions — throw
            throw new Error('Mocked extensions error');
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse certificate extensions',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given certificate contains an unknown critical extension', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          const realExtensionsGetter = Object.getOwnPropertyDescriptor(
            X509Certificate.prototype,
            'extensions',
          )!.get!;
          vi.spyOn(
            X509Certificate.prototype,
            'extensions',
            'get',
          ).mockImplementation(function (this: X509Certificate) {
            return [
              ...realExtensionsGetter.call(this),
              { type: '1.2.3.4', critical: true, value: new ArrayBuffer(0) },
            ];
          });
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate contains an unknown critical extension',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });

    describe('Given signature value validation fails', () => {
      describe('Given signature value parsing throws unexpectedly', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              const parsed = asnConvertParse(...args);
              if (
                parsed &&
                typeof parsed === 'object' &&
                'signatureValue' in parsed
              ) {
                Object.defineProperty(parsed, 'signatureValue', {
                  get() {
                    throw new Error('Mocked signatureValue error');
                  },
                });
              }
              return parsed;
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Failed to parse certificate signature value',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });

      describe('Given signature value is empty', () => {
        beforeEach(async () => {
          const { caCertPem, leafCertPem } =
            await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
          vi.spyOn(AsnConvert, 'parse').mockImplementation(
            (...args: Parameters<typeof AsnConvert.parse>) => {
              const parsed = asnConvertParse(...args);
              if (
                parsed &&
                typeof parsed === 'object' &&
                'signatureValue' in parsed
              ) {
                parsed.signatureValue = new ArrayBuffer(0);
              }
              return parsed;
            },
          );
          result = validateLeafCertificate({
            certPem: leafCertPem,
            csrSubjectCn: MOCK_CSR_SUBJECT_CN,
            certificateChain: caCertPem,
          });
        });

        it('Logs error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode:
              'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
            errorMessage: 'Certificate signature value must be present',
          });
        });

        it('Returns an empty failure', () => {
          expect(result).toEqual(emptyFailure());
        });
      });
    });
  });
  describe('Given leaf certificate is valid', () => {
    beforeEach(async () => {
      const { caCertPem, leafCertPem } =
        await createCaAndLeafCertPem(MOCK_CSR_SUBJECT_CN);
      result = validateLeafCertificate({
        certPem: leafCertPem,
        csrSubjectCn: MOCK_CSR_SUBJECT_CN,
        certificateChain: caCertPem,
      });
    });

    it('Returns empty success', () => {
      expect(result).toEqual(emptySuccess());
    });
  });
});
