import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  IssueCertificateCommand,
  GetCertificateCommand,
} from '@aws-sdk/client-acm-pca';
import {
  EXTENDED_KEY_USAGE,
  KEY_USAGE,
  SIGNING_ALGORITHM,
  TEMPLATE_ARN,
  VALIDITY,
} from '../common/certificate-service-constants/certificate-service-constants.ts';
import { getCertificate, issueCertificate } from './certificate-service.ts';
import { Result } from '../common/result/result.ts';

const { mockSend } = vi.hoisted(() => ({ mockSend: vi.fn() }));

vi.mock('@aws-sdk/client-acm-pca', () => ({
  ACMPCAClient: vi.fn().mockImplementation(function () {
    return { send: mockSend };
  }),
  IssueCertificateCommand: vi.fn(),
  GetCertificateCommand: vi.fn(),
}));

let result: Result<string, void>;
let certificate: string;
let certificateChain: string;
const mockCaArn =
  'arn:aws:acm-pca:eu-west-2:111111111111:certificate-authority/mock';
const mockCertificateArn = `${mockCaArn}/certificate/mock`;
const mockCsr =
  '-----BEGIN CERTIFICATE REQUEST-----\nMOCK\n-----END CERTIFICATE REQUEST-----';

describe('Certificate Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('issueCertificate', () => {
    describe('Given ACM PCA returns a certificate ARN', () => {
      beforeEach(async () => {
        mockSend.mockResolvedValue({ CertificateArn: mockCertificateArn });
        result = await issueCertificate(mockCsr, mockCaArn);
      });

      it('calls IssueCertificateCommand with the correct parameters', async () => {
        expect(IssueCertificateCommand).toHaveBeenCalledWith(
          expect.objectContaining({
            ApiPassthrough: expect.objectContaining({
              Extensions: expect.objectContaining({
                KeyUsage: { DigitalSignature: KEY_USAGE.DigitalSignature },
                ExtendedKeyUsage: [
                  {
                    ExtendedKeyUsageObjectIdentifier:
                      EXTENDED_KEY_USAGE[0].ExtendedKeyUsageObjectIdentifier,
                  },
                ],
              }),
            }),
            SigningAlgorithm: SIGNING_ALGORITHM,
            TemplateArn: TEMPLATE_ARN,
            Validity: { Type: VALIDITY.Type, Value: VALIDITY.Value },
          }),
        );
      });

      it('returns success with the certificate ARN', async () => {
        expect(result).toEqual({ isError: false, value: mockCertificateArn });
      });
    });

    describe('Given ACM PCA returns no certificate ARN', () => {
      it('returns an error result', async () => {
        mockSend.mockResolvedValue({});
        result = await issueCertificate(mockCsr, mockCaArn);
        expect(result.isError).toBe(true);
      });
    });

    describe('Given ACM PCA throws', () => {
      it('returns an error result', async () => {
        mockSend.mockRejectedValue(new Error('ACM PCA error'));
        result = await issueCertificate(mockCsr, mockCaArn);
        expect(result.isError).toBe(true);
      });
    });
  });

  describe('getCertificate', () => {
    beforeEach(async () => {
      mockSend.mockResolvedValue({
        Certificate:
          '-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----',
      });
      certificate =
        '-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----';
      certificateChain =
        '-----BEGIN CERTIFICATE-----\nMOCK_CHAIN\n-----END CERTIFICATE-----';
      result = await getCertificate(mockCertificateArn, mockCaArn);
    });
    describe('Given ACM PCA returns a certificate', () => {
      it('calls GetCertificateCommand with the provided ARNs', async () => {
        expect(GetCertificateCommand).toHaveBeenCalledWith({
          CertificateArn: mockCertificateArn,
          CertificateAuthorityArn: mockCaArn,
        });
      });

      it('returns the certificate when there is no chain', async () => {
        mockSend.mockResolvedValue({ Certificate: certificate });
        expect(result).toEqual({ isError: false, value: certificate });
      });

      it('concatenates certificate and chain when chain is present', async () => {
        mockSend.mockResolvedValue({
          Certificate: certificate,
          CertificateChain: certificateChain,
        });
        result = await getCertificate(mockCertificateArn, mockCaArn);

        expect(result).toEqual({
          isError: false,
          value: `${certificate}\n${certificateChain}`,
        });
      });
    });

    describe('Given ACM PCA throws RequestInProgressException then succeeds', () => {
      it('retries and returns success', async () => {
        const inProgressError = Object.assign(new Error(), {
          name: 'RequestInProgressException',
        });
        vi.clearAllMocks();
        mockSend
          .mockRejectedValueOnce(inProgressError)
          .mockResolvedValue({ Certificate: certificate });

        result = await getCertificate(mockCertificateArn, mockCaArn);

        expect(result).toEqual({ isError: false, value: certificate });
        expect(mockSend).toHaveBeenCalledTimes(2);
      });
    });

    describe('Given ACM PCA throws a non-retryable error', () => {
      it('returns an error result', async () => {
        mockSend.mockRejectedValue(new Error('Access denied'));

        result = await getCertificate(mockCertificateArn, mockCaArn);

        expect(result.isError).toBe(true);
      });
    });
  });
});
