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
  });

  describe('Lambda Function', () => {
    let nonceFunction: Record<string, unknown>;

    beforeAll(() => {
      nonceFunction = template.Resources.NonceServiceFunction as Record<string, unknown>;
    });

    it('should exist and be of correct type', () => {
      expect(nonceFunction).toBeDefined();
      expect(nonceFunction.Type).toBe('AWS::Serverless::Function');
    });

    it('should have correct function name pattern', () => {
      const properties = nonceFunction.Properties as Record<string, unknown>;
      expect(properties.FunctionName).toEqual({ 'Fn::Sub': '${AWS::StackName}-${Environment}-nonce-service' });
    });

    it('should have correct handler', () => {
      const properties = nonceFunction.Properties as Record<string, unknown>;
      expect(properties.Handler).toBe('handler.handler');
    });

    it('should have VPC configuration', () => {
      const properties = nonceFunction.Properties as Record<string, unknown>;
      const vpcConfig = properties.VpcConfig as Record<string, unknown>;
      expect(vpcConfig.SecurityGroupIds).toBeDefined();
      expect(vpcConfig.SubnetIds).toBeDefined();
    });

    it('should have environment variables', () => {
      const properties = nonceFunction.Properties as Record<string, unknown>;
      const environment = properties.Environment as Record<string, unknown>;
      const variables = environment.Variables as Record<string, unknown>;
      expect(variables.NONCE_TABLE_NAME).toBeDefined();
    });
  });

  describe('IAM Role', () => {
    let role: Record<string, unknown>;

    beforeAll(() => {
      role = template.Resources.NonceServiceRole as Record<string, unknown>;
    });

    it('should exist and be of correct type', () => {
      expect(role).toBeDefined();
      expect(role.Type).toBe('AWS::IAM::Role');
    });

    it('should have Lambda assume role policy', () => {
      const assumeRolePolicy = role.Properties as Record<string, unknown>;
      const statements = (assumeRolePolicy.AssumeRolePolicyDocument as Record<string, unknown>).Statement as Record<
        string,
        unknown
      >[];
      expect((statements[0].Principal as Record<string, unknown>).Service).toBe('lambda.amazonaws.com');
      expect(statements[0].Action).toBe('sts:AssumeRole');
    });

    it('should have DynamoDB permissions', () => {
      const properties = role.Properties as Record<string, unknown>;
      const policies = properties.Policies as Record<string, unknown>[];
      const dynamoPolicy = policies.find((p: Record<string, unknown>) => p.PolicyName === 'DynamoDBAccess');
      expect(dynamoPolicy).toBeDefined();
      const policyDoc = (dynamoPolicy as Record<string, unknown>).PolicyDocument as Record<string, unknown>;
      const statements = policyDoc.Statement as Record<string, unknown>[];
      expect(statements[0].Action).toContain('dynamodb:PutItem');
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

  describe('Outputs', () => {
    it('should export API Gateway domain name', () => {
      const apiOutput = template.Outputs.ApiGatewayDomainName as Record<string, unknown>;
      expect(apiOutput.Description).toBe('API Gateway regional domain name for CloudFront origin');
      expect(apiOutput.Value).toBeDefined();
    });

    it('should export API Gateway ID', () => {
      const apiIdOutput = template.Outputs.ApiGatewayId as Record<string, unknown>;
      expect(apiIdOutput.Description).toBe('API Gateway ID');
      expect(apiIdOutput.Value).toEqual({ Ref: 'CaBackendApi' });
    });

    it('should have all required outputs', () => {
      expect(() => testRequiredOutputs(template, ['ApiGatewayDomainName', 'ApiGatewayId', 'ApiStage'])).not.toThrow();
    });
  });
});
