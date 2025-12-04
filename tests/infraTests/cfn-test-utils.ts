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

export const ENVIRONMENT_VALUES = ['dev', 'build', 'staging', 'integration', 'prod'];
