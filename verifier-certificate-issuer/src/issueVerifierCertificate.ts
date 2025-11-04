import { createCertificateRequestFromEs256KmsKey } from './adapters/peculiar/peculiarAdapter';
import { logger } from './logging/logger';
import { Context } from 'aws-lambda';
import { getConfigFromEnvironment } from './issueVerifierCertificateConfig';
import { LogMessage } from './logging/LogMessages';
import { headObject, putObject } from './adapters/aws/s3Adapter';
import { getSsmParameter } from './adapters/aws/ssmAdapter';
import {
  issueMdlVerifierCertificateUsingSha256WithEcdsa,
  retrieveIssuedCertificate,
} from './adapters/aws/acmPcaAdapter';

export type IssueDocumentSigningCertificateDependencies = {
  env: NodeJS.ProcessEnv;
};

const dependencies: IssueDocumentSigningCertificateDependencies = {
  env: process.env,
};

export const handler = lambdaHandlerConstructor(dependencies);

export function lambdaHandlerConstructor(dependencies: IssueDocumentSigningCertificateDependencies) {
  return async (_event: unknown, context: Context) => {
    logger.addContext(context);
    logger.info(LogMessage.VERIFIER_CERT_ISSUER_STARTED);

    const configResult = getConfigFromEnvironment(dependencies.env);
    if (configResult.isError) {
      logger.error(LogMessage.VERIFIER_CERT_ISSUER_CONFIGURATION_FAILED);
      throw new Error('Invalid configuration');
    }
    const config = configResult.value;
    logger.info(LogMessage.VERIFIER_CERT_ISSUER_CONFIGURATION_SUCCESS, { config });

    const certificateAuthorityArn = await getSsmParameter(config.PLATFORM_CA_ARN_PARAMETER);
    const issuerAlternativeName = await getSsmParameter(config.PLATFORM_CA_ISSUER_ALTERNATIVE_NAME);
    const certificateAuthorityId = certificateAuthorityArn.split('/').pop();

    if (await headObject(config.VERIFIER_KEY_BUCKET, certificateAuthorityId + '/certificate.pem')) {
      logger.info(LogMessage.ROOT_CERTIFICATE_ALREADY_EXISTS);
    } else {
      const rootCertificate = await getSsmParameter(config.ROOT_CERTIFICATE);
      await putObject(config.VERIFIER_KEY_BUCKET, certificateAuthorityId + '/certificate.pem', rootCertificate);
      logger.info(LogMessage.ROOT_CERTIFICATE_UPLOADED);
    }

    if (await headObject(config.VERIFIER_KEY_BUCKET, config.VERIFIER_KEY_ID + '/certificate.pem')) {
      logger.error(LogMessage.VERIFIER_CERT_ISSUER_CERTIFICATE_ALREADY_EXISTS);
      throw new Error('Certificate already exists for this KMS Key');
    }

    try {
      const csr = await createCertificateRequestFromEs256KmsKey(
        config.VERIFIER_KEY_COMMON_NAME,
        config.VERIFIER_KEY_COUNTRY_NAME,
        config.VERIFIER_KEY_ID,
      );

      const issuedCertificateArn = await issueMdlVerifierCertificateUsingSha256WithEcdsa(
        issuerAlternativeName,
        certificateAuthorityArn,
        Buffer.from(csr),
        Number(config.VERIFIER_KEY_VALIDITY_PERIOD),
      );

      const issuedCertificate = await retrieveIssuedCertificate(issuedCertificateArn, certificateAuthorityArn);
      await putObject(config.VERIFIER_KEY_BUCKET, config.VERIFIER_KEY_ID + '/certificate.pem', issuedCertificate);

      logger.info(LogMessage.VERIFIER_CERT_ISSUER_CERTIFICATE_ISSUED);
    } catch (error) {
      logger.error(LogMessage.VERIFIER_CERT_ISSUER_CERTIFICATE_ISSUE_FAILED, { data: error });
      throw error;
    }
  };
}
