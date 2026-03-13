export interface MockJwksHandlerDependencies {
  env: NodeJS.ProcessEnv;
}

export const dependencies: MockJwksHandlerDependencies = {
  env: process.env,
};
