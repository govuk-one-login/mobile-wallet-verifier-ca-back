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
} from './certificate-service.ts';

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
  ) => Promise<Result<string, void>>;
}

export const dependencies: IssueReaderCertDependencies = {
  env: process.env,
  verifyAppCheckJwt,
  issueCertificate,
  getCertificate,
};
