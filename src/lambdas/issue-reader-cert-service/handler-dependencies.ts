import { Result } from '../common/result/result.ts';
import {
  ExpectedAppCheckJwtData,
  verifyAppCheckJwt,
  VerifyAppCheckJwtDependencies,
} from './verify-app-check-jwt/verify-app-check-jwt.ts';

export interface IssueReaderCertDependencies {
  env: NodeJS.ProcessEnv;
  verifyAppCheckJwt: (
    jwt: string,
    jwksUrl: string,
    expectedJwtData: ExpectedAppCheckJwtData,
    dependencies?: VerifyAppCheckJwtDependencies,
  ) => Promise<Result<void>>;
}

export const dependencies: IssueReaderCertDependencies = {
  env: process.env,
  verifyAppCheckJwt,
};
