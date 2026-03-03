import { ErrorCategory, errorResult, Result } from '../common/result/result';
import { describe, it, beforeEach, expect } from 'vitest';

describe('Verify JWT', () => {
  let result: Result<void, void>;
  describe('Given JWT is in invalid compact JWT format', () => {
    beforeEach(async () => {
      result = await verifyJwt('invalidFormatJwt');
    });

    it('Returns error result with client error', () => {
      expect(result).toEqual(
        errorResult({
          errorMessage: 'Invalid JWT format',
          errorCategory: ErrorCategory.CLIENT_ERROR,
        }),
      );
    });
  });
});
