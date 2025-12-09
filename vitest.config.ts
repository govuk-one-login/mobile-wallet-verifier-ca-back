import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/**',
        '**/*.test.ts',
        'vitest.config.ts',
        'eslint.config.ts',
        'tests/**',
        'scripts/**',
        'src/lambdas/generate-mock-issue-cert/**',
      ],
    },
  },
});
