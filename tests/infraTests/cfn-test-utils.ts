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
  ...createCfnType('!ImportValue', 'Fn::ImportValue'),
  ...createCfnType('!If', 'Fn::If'),
  ...createCfnType('!Not', 'Fn::Not'),
  ...createCfnType('!Equals', 'Fn::Equals'),
  ...createCfnType('!Or', 'Fn::Or'),
  ...createCfnType('!And', 'Fn::And'),
  ...createCfnType('!Condition', 'Condition'),
  ...createCfnType('!Join', 'Fn::Join'),
  ...createCfnType('!Select', 'Fn::Select'),
  ...createCfnType('!Split', 'Fn::Split'),
];

// Utility Functions
export function loadCloudFormationTemplate(
  templatePath: string,
): CloudFormationTemplate {
  const templateContent = readFileSync(templatePath, 'utf8');
  const cfnSchema = DEFAULT_SCHEMA.extend(cfnTypes);
  return load(templateContent, { schema: cfnSchema }) as CloudFormationTemplate;
}

export const ENVIRONMENT_VALUES = [
  'dev',
  'build',
  'staging',
  'integration',
  'prod',
];

// Common test helpers
export function testTemplateStructure(template: CloudFormationTemplate) {
  if (template.AWSTemplateFormatVersion !== '2010-09-09')
    throw new Error('Invalid AWSTemplateFormatVersion');
  if (template.Transform !== 'AWS::Serverless-2016-10-31')
    throw new Error('Invalid Transform');
  if (!template.Description?.includes('Verifier Certificate Authority backend'))
    throw new Error('Invalid Description');
}

export function testRequiredSections(
  template: CloudFormationTemplate,
  includeGlobals = false,
) {
  if (!template.Parameters) throw new Error('Parameters not defined');
  if (!template.Resources) throw new Error('Resources not defined');
  if (!template.Outputs) throw new Error('Outputs not defined');
  if (includeGlobals && !template.Globals)
    throw new Error('Globals not defined');
}

export function testEnvironmentParameter(template: CloudFormationTemplate) {
  const envParam = template.Parameters.Environment as Record<string, unknown>;
  if (envParam.Type !== 'String') throw new Error('Invalid Environment Type');
  if (envParam.Default !== 'dev')
    throw new Error('Invalid Environment Default');
  if (
    JSON.stringify(envParam.AllowedValues) !==
    JSON.stringify(ENVIRONMENT_VALUES)
  )
    throw new Error('Invalid AllowedValues');
}

export function testRequiredParameters(
  template: CloudFormationTemplate,
  params: string[],
) {
  params.forEach((param) => {
    if (!template.Parameters[param])
      throw new Error(`Parameter ${param} not defined`);
  });
}

export function testRequiredOutputs(
  template: CloudFormationTemplate,
  outputs: string[],
) {
  outputs.forEach((output) => {
    if (!template.Outputs[output])
      throw new Error(`Output ${output} not defined`);
  });
}
