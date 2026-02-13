import { describe, it, expect, beforeAll } from 'vitest';
import { join } from 'path';
import {
  CloudFormationTemplate,
  loadCloudFormationTemplate,
  testTemplateStructure,
  testRequiredSections,
  testEnvironmentParameter,
  testRequiredParameters,
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
      expect(() =>
        testRequiredParameters(template, ['Environment']),
      ).not.toThrow();
    });
  });
});
