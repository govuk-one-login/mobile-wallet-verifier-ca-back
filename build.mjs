import { build } from 'esbuild';
import { glob } from 'glob';

const entryPoints = await glob('src/lambdas/*/handler.ts');

await build({
  entryPoints,
  bundle: true,
  outdir: 'dist',
  outExtension: { '.js': '.mjs' },
  format: 'esm',
  platform: 'node',
  target: 'node22',
  sourcemap: true,
  external: ['@aws-sdk/*'],
  minify: false,
  keepNames: true,
});

console.log('Build completed successfully');