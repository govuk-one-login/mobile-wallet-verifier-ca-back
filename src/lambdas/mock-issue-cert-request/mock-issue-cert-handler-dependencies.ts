export interface GenerateMockIssueCertDependencies {
  env: NodeJS.ProcessEnv;
}

export const dependencies: GenerateMockIssueCertDependencies = {
  env: process.env,
};
