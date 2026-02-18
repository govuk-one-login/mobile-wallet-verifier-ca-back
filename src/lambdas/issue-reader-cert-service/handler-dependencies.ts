export interface IssueReaderCertDependencies {
    env: NodeJS.ProcessEnv;
}
export const dependencies: IssueReaderCertDependencies = {
    env: process.env
}