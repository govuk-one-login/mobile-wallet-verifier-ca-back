export interface IssueReaderCertDependencies {
  env: NodeJS.ProcessEnv | Record<string, string | string[]>;
}

export const dependencies: IssueReaderCertDependencies = {
  env: process.env,
};
