import { build } from 'esbuild';
import { glob } from 'glob';
import path from 'path';

interface EntryPoints {
  [outputPath: string]: string;
}

async function buildLambdas(): Promise<void> {
  // Find all handler files
  const handlerFiles: string[] = glob.sync('src/lambdas/**/handler.ts');
  
  const entryPoints: EntryPoints = handlerFiles.reduce((acc: EntryPoints, file: string) => {
    const relativePath: string = path.relative('src', file);
    const outputPath: string = relativePath.replace('.ts', '');
    acc[outputPath] = file;
    return acc;
  }, {} as EntryPoints);

  await build({
    entryPoints,
    bundle: true,
    outdir: 'dist',
    platform: 'node',
    target: 'node22',
    format: 'cjs',
    sourcemap: false,
    minify: true,
    external: ['@aws-sdk/*'],
    tsconfig: 'tsconfig.json'
  });

  console.log('Lambda functions built successfully');
}

buildLambdas().catch(console.error);