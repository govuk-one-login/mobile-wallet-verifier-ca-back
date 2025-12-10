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

describe('Base Application Infrastructure', () => {
  let template: CloudFormationTemplate;

  beforeAll(() => {
    const templatePath = join(__dirname, '../../base-application.yaml');
    template = loadCloudFormationTemplate(templatePath);
  });

  describe('Template Structure', () => {
    it('should have valid CloudFormation format', () => {
      expect(() => testTemplateStructure(template)).not.toThrow();
    });

    it('should have required sections', () => {
      expect(() => testRequiredSections(template)).not.toThrow();
    });
  });

  describe('Parameters', () => {
    it('should have Environment parameter with correct values', () => {
      expect(() => testEnvironmentParameter(template)).not.toThrow();
    });

    it('should have all required parameters', () => {
      expect(() => testRequiredParameters(template, ['Environment'])).not.toThrow();
    });
  });

  describe('DynamoDB NonceTable', () => {
    let nonceTable: Record<string, unknown>;

    beforeAll(() => {
      nonceTable = template.Resources.NonceTable as Record<string, unknown>;
    });

    it('should exist and be of correct type', () => {
      expect(nonceTable).toBeDefined();
      expect(nonceTable.Type).toBe('AWS::DynamoDB::Table');
    });

    it('should have correct table name pattern', () => {
      const properties = nonceTable.Properties as Record<string, unknown>;
      expect(properties.TableName).toEqual({ 'Fn::Sub': '${Environment}-nonce-store' });
    });

    it('should use pay-per-request billing', () => {
      const properties = nonceTable.Properties as Record<string, unknown>;
      expect(properties.BillingMode).toBe('PAY_PER_REQUEST');
    });

    it('should have correct key schema', () => {
      const properties = nonceTable.Properties as Record<string, unknown>;
      const keySchema = properties.KeySchema as Record<string, unknown>[];
      expect(keySchema).toHaveLength(1);
      expect(keySchema[0]).toEqual({
        AttributeName: 'nonceValue',
        KeyType: 'HASH',
      });
    });

    it('should have correct attribute definitions', () => {
      const properties = nonceTable.Properties as Record<string, unknown>;
      const attributeDefinitions = properties.AttributeDefinitions as Record<string, unknown>[];
      expect(attributeDefinitions).toHaveLength(1);
      expect(attributeDefinitions[0]).toEqual({
        AttributeName: 'nonceValue',
        AttributeType: 'S',
      });
    });

    it('should have TTL enabled', () => {
      const properties = nonceTable.Properties as Record<string, unknown>;
      const ttlSpec = properties.TimeToLiveSpecification as Record<string, unknown>;
      expect(ttlSpec.AttributeName).toBe('timeToLive');
      expect(ttlSpec.Enabled).toBe(true);
    });

    it('should have encryption enabled', () => {
      const properties = nonceTable.Properties as Record<string, unknown>;
      const sseSpec = properties.SSESpecification as Record<string, unknown>;
      expect(sseSpec.SSEEnabled).toBe(true);
    });
  });

  describe('Outputs', () => {
    it('should export NonceTableName', () => {
      const tableOutput = template.Outputs.NonceTableName as Record<string, unknown>;
      expect(tableOutput.Description).toBe('Name of the DynamoDB nonce table');
      expect(tableOutput.Value).toEqual({ Ref: 'NonceTable' });
      const exportInfo = tableOutput.Export as Record<string, unknown>;
      expect(exportInfo.Name).toEqual({ 'Fn::Sub': '${Environment}-nonce-store' });
    });

    it('should have all required outputs', () => {
      expect(() => testRequiredOutputs(template, ['NonceTableName'])).not.toThrow();
    });
  });
});
