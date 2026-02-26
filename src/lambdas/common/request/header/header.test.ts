import { getHeader, parseCacheControlHeader } from './header.ts';
import { describe, it, expect } from 'vitest';

describe('Header', () => {
  describe('getHeader', () => {
    describe('Given no headers are present', () => {
      it('Returns undefined', () => {
        expect(getHeader({}, 'example-header')).toBeUndefined();
      });
    });

    describe('Given header is not present', () => {
      it('Returns undefined', () => {
        expect(
          getHeader(
            { 'example-header': 'example-value' },
            'another-example-header',
          ),
        ).toBeUndefined();
      });
    });

    describe('Given header is present and casing is identical', () => {
      it('Returns header value', () => {
        expect(
          getHeader({ 'example-header': 'example-value' }, 'example-header'),
        ).toBe('example-value');
      });
    });

    describe('Given header is present in lowercase and uppercase header is requested', () => {
      it('Returns header value', () => {
        expect(
          getHeader({ 'example-header': 'example-value' }, 'EXAMPLE-HEADER'),
        ).toBe('example-value');
      });
    });

    describe('Given header is present in uppercase and lowercase header is requested', () => {
      it('Returns header value', () => {
        expect(
          getHeader({ 'EXAMPLE-HEADER': 'example-value' }, 'example-header'),
        ).toBe('example-value');
      });
    });

    describe('Given header is present in arbitrary case and arbitrarily cased header is requested', () => {
      it('Returns header value', () => {
        expect(
          getHeader({ 'ExAmpLe-hEADer': 'example-value' }, 'examPlE-HEadEr'),
        ).toBe('example-value');
      });
    });

    describe('Given header is present with multiple casings', () => {
      it('Returns header value of last defined header', () => {
        expect(
          getHeader(
            {
              'example-header': 'example-value',
              'EXAMPLE-HEADER': 'another-example-value',
            },
            'example-header',
          ),
        ).toBe('another-example-value');
      });
    });
  });

  const testData = [
    {
      scenario: 'Given header is undefined',
      cacheControlHeaderValue: undefined,
      expectedMaxAge: 0,
    },
    {
      scenario: 'Given header does not include max-age directive',
      cacheControlHeaderValue: 'no-store',
      expectedMaxAge: 0,
    },
    {
      scenario: 'Given header contains multiple max-age directives',
      cacheControlHeaderValue: 'max-age=60, max-age=120',
      expectedMaxAge: 0,
    },
    {
      scenario:
        'Given header contains multiple max-age directives with different casing',
      cacheControlHeaderValue: 'max-age=60, MaX-aGe=120',
      expectedMaxAge: 0,
    },
    {
      scenario: 'Given header contains max-age directive without a value',
      cacheControlHeaderValue: 'max-age',
      expectedMaxAge: 0,
    },
    {
      scenario:
        'Given header contains max-age directive with equals sign but no value',
      cacheControlHeaderValue: 'max-age=',
      expectedMaxAge: 0,
    },
    {
      scenario:
        'Given header contains max-age directive with a non-numeric value',
      cacheControlHeaderValue: 'max-age=invalid',
      expectedMaxAge: 0,
    },
    {
      scenario:
        'Given header contains max-age directive with a non-integer numeric value',
      cacheControlHeaderValue: 'max-age=1.5',
      expectedMaxAge: 0,
    },
    {
      scenario:
        'Given header contains max-age directive with a negative integer value',
      cacheControlHeaderValue: 'max-age=-1',
      expectedMaxAge: 0,
    },
    {
      scenario:
        'Given header contains valid max-age directive (non-negative integer value)',
      cacheControlHeaderValue: 'max-age=60',
      expectedMaxAge: 60,
    },
    {
      scenario:
        'Given header contains valid max-age directive with other directives',
      cacheControlHeaderValue: 'max-age=60, public',
      expectedMaxAge: 60,
    },
    {
      scenario:
        'Given header contains valid max-age directive with other directives and padding',
      cacheControlHeaderValue: 'public, max-age=60',
      expectedMaxAge: 60,
    },
    {
      scenario:
        'Given header contains valid max-age directive not in all lowercase',
      cacheControlHeaderValue: 'public, MaX-aGe=60',
      expectedMaxAge: 60,
    },
  ];

  describe('parseCacheControlHeader', () => {
    describe.each(testData)(
      '$scenario',
      ({ cacheControlHeaderValue, expectedMaxAge }) => {
        it(`Returns max age value of ${expectedMaxAge}`, () => {
          expect(parseCacheControlHeader(cacheControlHeaderValue)).toEqual({
            maxAge: expectedMaxAge,
          });
        });
      },
    );
  });
});
