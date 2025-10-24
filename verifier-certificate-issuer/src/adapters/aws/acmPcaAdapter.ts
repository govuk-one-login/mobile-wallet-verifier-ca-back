import {
  ACMPCAClient,
  GetCertificateCommand,
  GetCertificateCommandOutput,
  IssueCertificateCommand,
  RequestInProgressException,
} from '@aws-sdk/client-acm-pca';

const pcaClient = new ACMPCAClient();

export async function issueMdlVerifierCertificateUsingSha256WithEcdsa(
  issuerAlternativeName: string,
  certificateAuthorityArn: string,
  certificateSigningRequest: Uint8Array<ArrayBufferLike>,
  validityPeriod: number,
) {
  const issueCertificateCommand = new IssueCertificateCommand({
    ApiPassthrough: {
      Extensions: {
        KeyUsage: {
          DigitalSignature: true,
        },
        ExtendedKeyUsage: [
          {
            // mDL Reader Auth
            ExtendedKeyUsageObjectIdentifier: '1.0.18013.5.1.6',
          },
          {
            // mdocReaderAuth
            ExtendedKeyUsageObjectIdentifier: '1.0.23220.4.1.6',
          },
        ],
        CustomExtensions: [
          {
            ObjectIdentifier: '2.5.29.18',
            Value: issuerAlternativeName,
          },
        ],
      },
    },
    CertificateAuthorityArn: certificateAuthorityArn,
    Csr: certificateSigningRequest,
    SigningAlgorithm: 'SHA256WITHECDSA',
    TemplateArn: 'arn:aws:acm-pca:::template/BlankEndEntityCertificate_APIPassthrough/V1',
    Validity: {
      Value: validityPeriod,
      Type: 'DAYS',
    },
  });

  const issueCertificateCommandOutput = await pcaClient.send(issueCertificateCommand);
  if (issueCertificateCommandOutput.CertificateArn === undefined) {
    throw new Error('Failed to issue certificate');
  }

  return issueCertificateCommandOutput.CertificateArn;
}

export async function retrieveIssuedCertificate(
  issuedCertificateArn: string,
  certificateAuthorityArn: string,
  timeoutMs: number = 10000,
  maxRetries: number = 10 // Added maxRetries parameter
): Promise<string> {  // Return type corrected to string (Certificate data is a string)

    const getCertificate = async (): Promise<GetCertificateCommandOutput | undefined> => {
    const getCertificateCommand = new GetCertificateCommand({
      CertificateArn: issuedCertificateArn,
      CertificateAuthorityArn: certificateAuthorityArn,
    });
    try {
      return await pcaClient.send(getCertificateCommand);
    } catch (e) {
      if (!RequestInProgressException.isInstance(e)) {
        throw e;
      }
    }
  };

 async function getCertificateWithTimeout(timeoutMs: number, maxRetries: number): Promise<GetCertificateCommandOutput> {
        let retries = 0;
        const startTime = Date.now(); // Record the start time for timeout calculation

        while (retries < maxRetries) {
            const remainingTime = timeoutMs - (Date.now() - startTime);
            if (remainingTime <= 0) {
                throw new Error('Request timed out');
            }

            const timeoutPromise = new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), remainingTime));

            const result = await Promise.race([getCertificate(), timeoutPromise]);

            if (result) {
                return result;
            }
            retries++;
        }
        throw new Error(`Request timed out after ${maxRetries} retries`);
    }

    const getCertificateCommandOutput = await getCertificateWithTimeout(timeoutMs, maxRetries);

  if (!getCertificateCommandOutput.Certificate) {
    throw new Error('Failed to retrieve certificate');
  }
  return getCertificateCommandOutput.Certificate;
}
