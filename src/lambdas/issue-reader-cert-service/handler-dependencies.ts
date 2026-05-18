import { Result } from '../common/result/result.ts';
import {
  ExpectedAppCheckJwtData,
  verifyAppCheckJwt,
  VerifyAppCheckJwtDependencies,
} from './verify-app-check-jwt/verify-app-check-jwt.ts';
import {
  issueCertificate,
  getCertificate,
  IssueCertificateParams,
  GetCertificateParams,
  CertificateResult,
} from './certificate-service.ts';
import {
  validateLeafCertificate,
  ValidateLeafCertificateParams,
} from '../common/validate-leaf-certificate/validate-leaf-certificate.ts';

export interface IssueReaderCertDependencies {
  env: NodeJS.ProcessEnv;
  verifyAppCheckJwt: (
    jwt: string,
    jwksUrl: string,
    expectedJwtData: ExpectedAppCheckJwtData,
    dependencies?: VerifyAppCheckJwtDependencies,
  ) => Promise<Result<void>>;
  issueCertificate: (
    params: IssueCertificateParams,
  ) => Promise<Result<string, void>>;
  getCertificate: (
    params: GetCertificateParams,
  ) => Promise<Result<CertificateResult, void>>;
  validateLeafCertificate: (
    params: ValidateLeafCertificateParams,
  ) => Result<void, void>;
}

export const dependencies: IssueReaderCertDependencies = {
  env: process.env,
  verifyAppCheckJwt,
  issueCertificate,
  getCertificate,
  validateLeafCertificate,
};
