import { readFileSync } from 'fs';
import { load, DEFAULT_SCHEMA, Type } from 'js-yaml';

// CloudFormation Template Interface
export interface CloudFormationTemplate {
  AWSTemplateFormatVersion: string;
  Transform: string;
  Description: string;
  Parameters: Record<string, unknown>;
  Resources: Record<string, unknown>;
  Outputs: Record<string, unknown>;
  Globals?: Record<string, unknown>;
  Mappings?: Record<string, unknown>;
  Conditions?: Record<string, unknown>;
}

// Handle CloudFormation intrinsic functions that can appear in different contexts
const createCfnType = (tag: string, fnName: string): Type[] => [
  new Type(tag, {
    kind: 'scalar',
    construct: (data: string) => ({ [fnName]: data }),
  }),
  new Type(tag, {
    kind: 'sequence',
    construct: (data: unknown[]) => ({ [fnName]: data }),
  }),
  new Type(tag, {
    kind: 'mapping',
    construct: (data: Record<string, unknown>) => ({ [fnName]: data }),
  }),
];

const cfnTypes: Type[] = [
  ...createCfnType('!Sub', 'Fn::Sub'),
  ...createCfnType('!Ref', 'Ref'),
  ...createCfnType('!GetAtt', 'Fn::GetAtt'),
  ...createCfnType('!FindInMap', 'Fn::FindInMap'),
  ...createCfnType('!If', 'Fn::If'),
  ...createCfnType('!Not', 'Fn::Not'),
  ...createCfnType('!Equals', 'Fn::Equals'),
  ...createCfnType('!Or', 'Fn::Or'),
  ...createCfnType('!Join', 'Fn::Join'),
  ...createCfnType('!Select', 'Fn::Select'),
  ...createCfnType('!Split', 'Fn::Split'),
];

// Utility Functions
export function loadCloudFormationTemplate(templatePath: string): CloudFormationTemplate {
  const templateContent = readFileSync(templatePath, 'utf8');
  const cfnSchema = DEFAULT_SCHEMA.extend(cfnTypes);
  return load(templateContent, { schema: cfnSchema }) as CloudFormationTemplate;
}

export function validateTemplateStructure(template: CloudFormationTemplate) {
  expect(template.AWSTemplateFormatVersion).toBe('2010-09-09');
  expect(template.Transform).toBe('AWS::Serverless-2016-10-31');
  expect(template.Description).toContain('Verifier Certificate Authority backend');
}

export function validateEnvironmentParameter(template: CloudFormationTemplate) {
  const envParam = template.Parameters.Environment as Record<string, unknown>;
  expect(envParam.Type).toBe('String');
  expect(envParam.Default).toBe('dev');
  expect(envParam.AllowedValues).toEqual(['dev', 'build', 'staging', 'integration', 'prod']);
}

export const ENVIRONMENT_VALUES = ['dev', 'build', 'staging', 'integration', 'prod'];
