import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { load, CORE_SCHEMA, Schema, defineScalarTag } from 'js-yaml';

// The spec uses only the !Sub CloudFormation tag (inside the integration URI).
const cfnSchema = new Schema([
  ...CORE_SCHEMA.tags,
  defineScalarTag('!Sub', {
    resolve: (data: string) => ({ 'Fn::Sub': data }),
    identify: () => false,
  }),
]);

interface OpenApiSpec {
  security?: Array<Record<string, unknown[]>>;
  paths: Record<string, Record<string, Record<string, unknown>>>;
  components: {
    securitySchemes?: Record<string, Record<string, unknown>>;
  };
  'x-amazon-apigateway-gateway-responses'?: Record<
    string,
    Record<string, unknown>
  >;
}

describe('OpenAPI spec - SigV4', () => {
  let spec: OpenApiSpec;
  let issueReaderCertPost: Record<string, unknown>;

  beforeAll(() => {
    const specPath = join(__dirname, '../../open-api-spec.yaml');
    spec = load(readFileSync(specPath, 'utf8'), {
      schema: cfnSchema,
    }) as OpenApiSpec;
    issueReaderCertPost = spec.paths['/issue-reader-cert'].post;
  });

  it('declares the sigv4 security scheme as an awsSigv4 authtype', () => {
    const scheme = spec.components.securitySchemes?.sigv4 as Record<
      string,
      unknown
    >;
    expect(scheme).toBeDefined();
    expect(scheme.type).toBe('apiKey');
    expect(scheme.name).toBe('Authorization');
    expect(scheme.in).toBe('header');
    expect(scheme['x-amazon-apigateway-authtype']).toBe('awsSigv4');
  });

  it('requires sigv4 on the /issue-reader-cert operation', () => {
    expect(issueReaderCertPost.security).toEqual([{ sigv4: [] }]);
  });

  it('applies sigv4 as a top-level default security requirement', () => {
    expect(spec.security).toEqual([{ sigv4: [] }]);
  });

  it('documents a 403 response', () => {
    const responses = issueReaderCertPost.responses as Record<string, unknown>;
    expect(responses['403']).toBeDefined();
  });

  it('maps missing/invalid signatures to a 403 gateway response', () => {
    const gatewayResponses = spec['x-amazon-apigateway-gateway-responses'];
    expect(gatewayResponses?.MISSING_AUTHENTICATION_TOKEN?.statusCode).toBe(
      403,
    );
  });
});
