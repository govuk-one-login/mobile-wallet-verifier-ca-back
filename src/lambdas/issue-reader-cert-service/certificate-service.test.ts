import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  MockInstance,
  afterEach,
} from 'vitest';
import {
  IssueCertificateCommand,
  GetCertificateCommand,
} from '@aws-sdk/client-acm-pca';
import {
  EXTENDED_KEY_USAGE_DER_BASE64,
  KEY_USAGE,
  SIGNING_ALGORITHM,
  TEMPLATE_ARN,
} from '../common/certificate-service-constants/certificate-service-constants.ts';
import {
  getCertificate,
  issueCertificate,
  CertificateResult,
} from './certificate-service.ts';
import {
  emptyFailure,
  Result,
  successResult,
} from '../common/result/result.ts';
import '../../../tests/testUtils/matchers.ts';

const { mockSend } = vi.hoisted(() => ({ mockSend: vi.fn() }));

vi.mock('@aws-sdk/client-acm-pca', () => ({
  ACMPCAClient: vi.fn().mockImplementation(function () {
    return { send: mockSend };
  }),
  IssueCertificateCommand: vi.fn(),
  GetCertificateCommand: vi.fn(),
}));

let getCertificateResult: Result<CertificateResult, void>;
let issueCertificateResult: Result<string, void>;
let certificate: string;
let certificateChain: string;
let consoleErrorSpy: MockInstance;
const mockCaArn =
  'arn:aws:acm-pca:eu-west-2:111111111111:certificate-authority/mock';
const mockCertificateArn = `${mockCaArn}/certificate/mock`;
const mockCsr =
  '-----BEGIN CERTIFICATE REQUEST-----\nMOCK\n-----END CERTIFICATE REQUEST-----';

describe('Certificate Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    consoleErrorSpy = vi.spyOn(console, 'error');
  });

  describe('issueCertificate', () => {
    describe('Given ACM PCA throws', () => {
      beforeEach(async () => {
        mockSend.mockRejectedValue(new Error('ACM PCA error'));
        issueCertificateResult = await issueCertificate({
          csrPem: mockCsr,
          certificateAuthorityArn: mockCaArn,
        });
      });

      it('logs ISSUE_READER_CERT_ISSUE_CERTIFICATE_FAILURE', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_ISSUE_READER_CERT_ISSUE_CERTIFICATE_FAILURE',
          errorMessage: 'Unexpected error issuing certificate',
        });
      });

      it('returns an error result', () => {
        expect(issueCertificateResult).toEqual(emptyFailure());
      });
    });

    describe('Given ACM PCA returns no certificate ARN', () => {
      beforeEach(async () => {
        mockSend.mockResolvedValue({});
        issueCertificateResult = await issueCertificate({
          csrPem: mockCsr,
          certificateAuthorityArn: mockCaArn,
        });
      });

      it('logs ISSUE_READER_CERT_ISSUE_CERTIFICATE_FAILURE', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_ISSUE_READER_CERT_ISSUE_CERTIFICATE_FAILURE',
          errorMessage: 'No certificate ARN returned',
        });
      });

      it('returns an error result', () => {
        expect(issueCertificateResult).toEqual(emptyFailure());
      });
    });

    describe('Given ACM PCA returns a certificate ARN', () => {
      beforeEach(async () => {
        mockSend.mockResolvedValue({ CertificateArn: mockCertificateArn });
        issueCertificateResult = await issueCertificate({
          csrPem: mockCsr,
          certificateAuthorityArn: mockCaArn,
        });
      });

      it('calls IssueCertificateCommand with the correct parameters', async () => {
        expect(IssueCertificateCommand).toHaveBeenCalledWith(
          expect.objectContaining({
            ApiPassthrough: expect.objectContaining({
              Extensions: expect.objectContaining({
                KeyUsage: { DigitalSignature: KEY_USAGE.DigitalSignature },
                CustomExtensions: [
                  {
                    ObjectIdentifier: '2.5.29.37',
                    Value: EXTENDED_KEY_USAGE_DER_BASE64,
                    Critical: true,
                  },
                ],
              }),
            }),
            SigningAlgorithm: SIGNING_ALGORITHM,
            TemplateArn: TEMPLATE_ARN,
            Validity: { Type: 'DAYS', Value: 1 },
          }),
        );
      });

      it('returns success with the certificate ARN', async () => {
        expect(issueCertificateResult).toEqual(
          successResult(mockCertificateArn),
        );
      });
    });
  });

  describe('getCertificate', () => {
    beforeEach(() => {
      certificate =
        '-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----';
      certificateChain =
        '-----BEGIN CERTIFICATE-----\nMOCK_CHAIN\n-----END CERTIFICATE-----';

      vi.spyOn(global, 'setTimeout').mockImplementation((callback) => {
        callback();
        return {} as NodeJS.Timeout;
      });
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    describe('Given ACM PCA keeps throwing RequestInProgressException', () => {
      beforeEach(async () => {
        const inProgressError = Object.assign(new Error(), {
          name: 'RequestInProgressException',
        });
        mockSend.mockRejectedValue(inProgressError);
        getCertificateResult = await getCertificate({
          certificateArn: mockCertificateArn,
          certificateAuthorityArn: mockCaArn,
        });
      });

      it('logs ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE',
          errorMessage: 'Certificate retrieval timed out after maximum retries',
        });
      });

      it('retries up to the retry limit', () => {
        expect(mockSend).toHaveBeenCalledTimes(3);
      });

      it('returns an error result after exhausting retries', () => {
        expect(getCertificateResult).toEqual(emptyFailure());
      });
    });

    describe('Given ACM PCA throws a non-retryable error', () => {
      beforeEach(async () => {
        mockSend.mockRejectedValue(new Error('Access denied'));
        getCertificateResult = await getCertificate({
          certificateArn: mockCertificateArn,
          certificateAuthorityArn: mockCaArn,
        });
      });

      it('logs ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE',
          errorMessage: 'Unexpected error retrieving certificate',
        });
      });

      it('returns an error result', () => {
        expect(getCertificateResult).toEqual(emptyFailure());
      });
    });

    describe('Given ACM PCA throws RequestInProgressException then succeeds', () => {
      beforeEach(async () => {
        const inProgressError = Object.assign(new Error(), {
          name: 'RequestInProgressException',
        });
        mockSend.mockRejectedValueOnce(inProgressError).mockResolvedValue({
          Certificate: certificate,
          CertificateChain: certificateChain,
        });

        getCertificateResult = await getCertificate({
          certificateArn: mockCertificateArn,
          certificateAuthorityArn: mockCaArn,
        });
      });

      it('retries one time (attempts two times)', () => {
        expect(mockSend).toHaveBeenCalledTimes(2);
      });

      it('retries and returns success', async () => {
        expect(getCertificateResult).toEqual(
          successResult({ certificate, certificateChain }),
        );
      });
    });

    describe('Given ACM PCA returns no certificate', () => {
      beforeEach(async () => {
        mockSend.mockResolvedValue({});
        getCertificateResult = await getCertificate({
          certificateArn: mockCertificateArn,
          certificateAuthorityArn: mockCaArn,
        });
      });

      it('logs ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE',
          errorMessage: 'Failed to retrieve certificate',
        });
      });

      it('returns an error result', () => {
        expect(getCertificateResult).toEqual(emptyFailure());
      });
    });

    describe('Given ACM PCA returns no certificate chain', () => {
      beforeEach(async () => {
        mockSend.mockResolvedValue({ Certificate: certificate });
        getCertificateResult = await getCertificate({
          certificateArn: mockCertificateArn,
          certificateAuthorityArn: mockCaArn,
        });
      });

      it('logs ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE',
          errorMessage: 'Failed to retrieve certificate chain',
        });
      });

      it('returns an error result', () => {
        expect(getCertificateResult).toEqual(emptyFailure());
      });
    });

    describe('Given ACM PCA returns a certificate and chain', () => {
      beforeEach(async () => {
        mockSend.mockResolvedValue({
          Certificate: certificate,
          CertificateChain: certificateChain,
        });
        getCertificateResult = await getCertificate({
          certificateArn: mockCertificateArn,
          certificateAuthorityArn: mockCaArn,
        });
      });

      it('calls GetCertificateCommand with the provided ARNs', () => {
        expect(GetCertificateCommand).toHaveBeenCalledWith({
          CertificateArn: mockCertificateArn,
          CertificateAuthorityArn: mockCaArn,
        });
      });

      it('returns certificate and chain', () => {
        expect(getCertificateResult).toEqual(
          successResult({ certificate, certificateChain }),
        );
      });
    });
  });
});
