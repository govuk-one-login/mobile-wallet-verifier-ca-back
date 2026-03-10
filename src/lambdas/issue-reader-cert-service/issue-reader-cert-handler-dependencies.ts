import { Result } from '../common/result/result.ts';
import {
  ExpectedJwtData,
  verifyJwt,
  VerifyJwtDependencies,
} from './verify-jwt/verify-jwt.ts';

export interface IssueReaderCertDependencies {
  env: NodeJS.ProcessEnv;
  verifyJwt: (
    jwt: string,
    jwksUrl: string,
    expectedJwtData: ExpectedJwtData,
    dependencies?: VerifyJwtDependencies,
  ) => Promise<Result<void>>;
}

export const dependencies: IssueReaderCertDependencies = {
  env: process.env,
  verifyJwt,
};
