import { describe, it, expect, beforeAll } from 'vitest';
import { join } from 'path';
import {
  CloudFormationTemplate,
  loadCloudFormationTemplate,
  testTemplateStructure,
  testRequiredSections,
  testEnvironmentParameter,
  testRequiredParameters,
  testRequiredOutputs,
  ENVIRONMENT_VALUES,
} from './cfn-test-utils';

describe('Application Infrastructure', () => {
  let template: CloudFormationTemplate;

  beforeAll(() => {
    const templatePath = join(__dirname, '../../application.yaml');
    template = loadCloudFormationTemplate(templatePath);
  });

  describe('Template Structure', () => {
    it('should have valid CloudFormation format', () => {
      expect(() => testTemplateStructure(template)).not.toThrow();
    });

    it('should have required sections', () => {
      expect(() => testRequiredSections(template, true)).not.toThrow();
    });
  });

  describe('Parameters', () => {
    it('should have Environment parameter', () => {
      expect(() => testEnvironmentParameter(template)).not.toThrow();
    });

    it('should have all required parameters', () => {
      expect(() =>
        testRequiredParameters(template, [
          'Environment',
          'CodeSigningConfigArn',
          'PermissionsBoundary',
          'VpcStackName',
        ]),
      ).not.toThrow();
    });

    it('should resolve the CA ARN from SSM using the Environment-derived path', () => {
      const templateJson = JSON.stringify(template);
      expect(templateJson).toContain(
        '{{resolve:ssm:/${Environment}/GovCA/CertificateAuthorityArn}}',
      );
    });
  });

  describe('Lambda Function', () => {
    let issueReaderCertFunction: Record<string, unknown>;

    beforeAll(() => {
      issueReaderCertFunction = template.Resources
        .IssueReaderCertServiceFunction as Record<string, unknown>;
    });

    it('should exist and be of correct type', () => {
      expect(issueReaderCertFunction).toBeDefined();
      expect(issueReaderCertFunction.Type).toBe('AWS::Serverless::Function');
    });

    it('should have correct function name pattern', () => {
      const properties = issueReaderCertFunction.Properties as Record<
        string,
        unknown
      >;
      expect(properties.FunctionName).toEqual({
        'Fn::Sub': '${AWS::StackName}-${Environment}-issue-reader-cert-service',
      });
    });

    it('should have correct handler', () => {
      const properties = issueReaderCertFunction.Properties as Record<
        string,
        unknown
      >;
      expect(properties.Handler).toBe(
        'src/lambdas/issue-reader-cert-service/handler.handler',
      );
    });

    it('should have a 15 second timeout', () => {
      const properties = issueReaderCertFunction.Properties as Record<
        string,
        unknown
      >;
      expect(properties.Timeout).toBe(15);
    });

    it('should have VPC configuration', () => {
      const properties = issueReaderCertFunction.Properties as Record<
        string,
        unknown
      >;
      const vpcConfig = properties.VpcConfig as Record<string, unknown>;
      expect(vpcConfig.SecurityGroupIds).toBeDefined();
      expect(vpcConfig.SubnetIds).toBeDefined();
    });
  });

  describe('Firebase App Check feature flag', () => {
    it('wires ENABLE_FIREBASE_APP_CHECK_JWT_VALIDATION from the EnvironmentVariables mapping', () => {
      const properties = (
        template.Resources.IssueReaderCertServiceFunction as Record<
          string,
          unknown
        >
      ).Properties as Record<string, unknown>;
      const environment = properties.Environment as Record<string, unknown>;
      const variables = environment.Variables as Record<string, unknown>;

      expect(variables.ENABLE_FIREBASE_APP_CHECK_JWT_VALIDATION).toEqual({
        'Fn::FindInMap': [
          'EnvironmentVariables',
          { Ref: 'Environment' },
          'EnableFirebaseAppCheckJwtValidation',
        ],
      });
    });

    it.each(ENVIRONMENT_VALUES)(
      "has Firebase App Check JWT validation disabled in the '%s' environment",
      (environmentName) => {
        const environmentVariables = (
          template.Mappings?.EnvironmentVariables as Record<
            string,
            Record<string, unknown>
          >
        )[environmentName];

        expect(environmentVariables.EnableFirebaseAppCheckJwtValidation).toBe(
          'false',
        );
      },
    );
  });

  describe('IAM Role', () => {
    let role: Record<string, unknown>;

    beforeAll(() => {
      role = template.Resources.IssueReaderCertServiceRole as Record<
        string,
        unknown
      >;
    });

    it('should exist and be of correct type', () => {
      expect(role).toBeDefined();
      expect(role.Type).toBe('AWS::IAM::Role');
    });

    it('should have Lambda assume role policy', () => {
      const assumeRolePolicy = role.Properties as Record<string, unknown>;
      const statements = (
        assumeRolePolicy.AssumeRolePolicyDocument as Record<string, unknown>
      ).Statement as Record<string, unknown>[];
      expect((statements[0].Principal as Record<string, unknown>).Service).toBe(
        'lambda.amazonaws.com',
      );
      expect(statements[0].Action).toBe('sts:AssumeRole');
    });
  });

  describe('SigV4 GitHub OIDC access', () => {
    it('gates the SigV4 access role behind the CreateSigV4AccessRole condition (all non-prod envs)', () => {
      const role = template.Resources.SigV4AccessRole as Record<
        string,
        unknown
      >;
      expect(role).toBeDefined();
      expect(role.Type).toBe('AWS::IAM::Role');
      expect(role.Condition).toBe('CreateSigV4AccessRole');
      expect(template.Conditions?.CreateSigV4AccessRole).toEqual({
        'Fn::Not': [{ Condition: 'IsProdEnvironment' }],
      });
    });

    it('trusts the imported GitHub OIDC provider with aud and hardcoded sub conditions', () => {
      const role = template.Resources.SigV4AccessRole as Record<
        string,
        unknown
      >;
      const properties = role.Properties as Record<string, unknown>;
      const statement = (
        (properties.AssumeRolePolicyDocument as Record<string, unknown>)
          .Statement as Record<string, unknown>[]
      )[0];

      const principal = statement.Principal as Record<string, unknown>;
      expect(principal.Federated).toEqual({
        'Fn::ImportValue': 'GitHubIdentityProviderArn',
      });

      expect(statement.Action).toBe('sts:AssumeRoleWithWebIdentity');
      const condition = statement.Condition as Record<
        string,
        Record<string, unknown>
      >;
      expect(
        condition.StringEquals['token.actions.githubusercontent.com:aud'],
      ).toBe('sts.amazonaws.com');
      expect(
        condition.StringLike['token.actions.githubusercontent.com:sub'],
      ).toEqual([
        'repo:govuk-one-login/mobile-credential-sharing-android:ref:refs/heads/main',
        'repo:govuk-one-login/mobile-verifier-spike-infra:ref:refs/heads/main',
      ]);
    });

    it('scopes the role to invoking only the /issue-reader-cert path', () => {
      const role = template.Resources.SigV4AccessRole as Record<
        string,
        unknown
      >;
      const properties = role.Properties as Record<string, unknown>;
      const policy = (properties.Policies as Record<string, unknown>[])[0];
      const statement = (
        (policy.PolicyDocument as Record<string, unknown>).Statement as Record<
          string,
          unknown
        >[]
      )[0];

      expect(statement.Action).toBe('execute-api:Invoke');
      expect(JSON.stringify(statement.Resource)).toContain(
        '/${Environment}/POST/issue-reader-cert',
      );
    });

    it('applies a resource policy to the CA backend API', () => {
      const api = template.Resources.CaBackendApi as Record<string, unknown>;
      const auth = (api.Properties as Record<string, unknown>).Auth as Record<
        string,
        unknown
      >;
      expect(auth).toBeDefined();
      const resourcePolicy = auth.ResourcePolicy as Record<string, unknown>;
      const statements = resourcePolicy.CustomStatements as Record<
        string,
        unknown
      >[];
      expect(statements.length).toBeGreaterThanOrEqual(1);
      expect(statements[0].Action).toBe('execute-api:Invoke');
    });
  });

  describe('Firewall Manager WAF', () => {
    it('leaves WAF ownership and stage association to Firewall Manager', () => {
      const wafResources = Object.values(template.Resources).filter(
        (resource) =>
          ['AWS::WAFv2::WebACL', 'AWS::WAFv2::WebACLAssociation'].includes(
            (resource as Record<string, unknown>).Type as string,
          ),
      );
      expect(wafResources).toEqual([]);
    });
  });

  describe('API Gateway', () => {
    let api: Record<string, unknown>;

    beforeAll(() => {
      api = template.Resources.CaBackendApi as Record<string, unknown>;
    });

    it('should exist and be of correct type', () => {
      expect(api).toBeDefined();
      expect(api.Type).toBe('AWS::Serverless::Api');
    });

    it('should have correct stage name', () => {
      const properties = api.Properties as Record<string, unknown>;
      expect(properties.StageName).toEqual({ Ref: 'Environment' });
    });

    it('should have tracing enabled', () => {
      const properties = api.Properties as Record<string, unknown>;
      expect(properties.TracingEnabled).toBe(true);
    });
  });

  describe('Custom domain mappings', () => {
    let mockBasePathMapping: Record<string, unknown>;

    beforeAll(() => {
      mockBasePathMapping = template.Resources
        .MockApiGatewayPublicBasePathMapping as Record<string, unknown>;
    });

    it('should only create the mock custom domain mapping when custom domains are enabled', () => {
      expect(mockBasePathMapping).toBeDefined();
      expect(mockBasePathMapping.Condition).toBe(
        'DeployMockCustomDomainResources',
      );
      expect(template.Conditions?.DeployMockCustomDomainResources).toEqual({
        'Fn::And': [
          { Condition: 'CreateCustomDomain' },
          { Condition: 'DeployMockResources' },
        ],
      });
    });
  });

  describe('Outputs', () => {
    it('should export API Gateway domain name', () => {
      const apiOutput = template.Outputs.ApiGatewayDomainName as Record<
        string,
        unknown
      >;
      expect(apiOutput.Description).toBe(
        'Direct regional API Gateway base URL',
      );
      expect(apiOutput.Value).toBeDefined();
    });

    it('exports mock services API base URL', () => {
      const mockServicesApiOutput = template.Outputs
        .MockServicesApiUrl as Record<string, unknown>;

      expect(mockServicesApiOutput.Description).toBe(
        'Mock services API base URL',
      );
      expect(mockServicesApiOutput.Value).toBeDefined();
      expect(mockServicesApiOutput.Condition).toBe('DeployMockResources');
    });

    it('should export API Gateway ID', () => {
      const apiIdOutput = template.Outputs.ApiGatewayId as Record<
        string,
        unknown
      >;
      expect(apiIdOutput.Description).toBe('API Gateway ID');
      expect(apiIdOutput.Value).toEqual({ Ref: 'CaBackendApi' });
    });

    it('should have all required outputs', () => {
      expect(() =>
        testRequiredOutputs(template, [
          'ApiGatewayDomainName',
          'ApiGatewayId',
          'ApiStage',
        ]),
      ).not.toThrow();
    });
  });
});
