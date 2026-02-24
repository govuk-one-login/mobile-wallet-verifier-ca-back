import {
  describe,
  it,
  afterEach,
  beforeEach,
  expect,
  MockInstance,
  vi,
  Mock,
} from 'vitest';
import '../../../../../../tests/testUtils/matchers';

import { InMemoryJwksCache } from '../JwksCache';
import { GetKeysResponse, JwksCacheDependencies } from '../types';
import {
  ISendHttpRequest,
  SuccessfulHttpResponse,
} from '../../../../adapters/http/sendHttpRequest';
import {
  Result,
  successResult,
  SuccessWithValue,
} from '../../../result/result.ts';
import { NOW_IN_MILLISECONDS } from '../../../../../../tests/testUtils/unitTestData.ts';

let inMemoryJwksCache: InMemoryJwksCache;
let dependencies: JwksCacheDependencies;
let result: Result<GetKeysResponse, void>;
let mockSendRequest: Mock<ISendHttpRequest>;
let consoleDebugSpy: MockInstance;

const MAXIMUM_CACHE_DURATION_SECONDS = 6 * 60 * 60; // 6 hours
const MAXIMUM_CACHE_DURATION_MILLIS = MAXIMUM_CACHE_DURATION_SECONDS * 1000;

const serverDefinedMaxAgeInSeconds = MAXIMUM_CACHE_DURATION_SECONDS - 1;

describe('InMemoryJwksCache - Caching', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW_IN_MILLISECONDS);

    consoleDebugSpy = vi.spyOn(console, 'debug');

    mockSendRequest = vi
      .fn<ISendHttpRequest>()
      .mockResolvedValue(
        buildSuccessfulJwksResponseWithKeyIdsAndMaxAge(
          ['mock_kid'],
          serverDefinedMaxAgeInSeconds,
        ),
      );
    dependencies = {
      sendRequest: mockSendRequest,
    };
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('getJwks', () => {
    describe('Given no previous requests to JWKS URI', () => {
      describe('Given getJwks is called with a JWKS URI', () => {
        beforeEach(async () => {
          inMemoryJwksCache = new InMemoryJwksCache(dependencies);
          result = await inMemoryJwksCache.getJwks('mock_jwks_uri');
        });

        it('Returns success with keys', () => {
          expect(result).toEqual(
            successResult({ keys: [{ kid: 'mock_kid' }] }),
          );
        });

        it('Calls JWKS URI', () => {
          expectJwksUriToHaveBeenCalledNTimes(
            mockSendRequest,
            'mock_jwks_uri',
            1,
          );
        });

        it('Logs MOBILE_CA_GET_JWKS_ATTEMPT with JWKS URI', () => {
          expect(consoleDebugSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_GET_JWKS_ATTEMPT',
            data: {
              jwksUri: 'mock_jwks_uri',
            },
          });
        });

        it('Logs MOBILE_CA_GET_JWKS_SUCCESS with JWKS URI', async () => {
          expect(consoleDebugSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_GET_JWKS_SUCCESS',
            data: {
              jwksUri: 'mock_jwks_uri',
            },
          });
        });
      });
    });

    describe('Given previous response from JWKS URI does not include Cache-Control header', () => {
      beforeEach(async () => {
        mockSendRequest = vi.fn().mockResolvedValue(
          successResult({
            statusCode: 200,
            body: JSON.stringify({
              keys: [{ kid: 'mock_kid' }],
            }),
            headers: {},
          }),
        );
        dependencies.sendRequest = mockSendRequest;

        inMemoryJwksCache = new InMemoryJwksCache(dependencies);
        await inMemoryJwksCache.getJwks('mock_jwks_uri');
        result = await inMemoryJwksCache.getJwks('mock_jwks_uri');
      });

      it('Returns success with keys', () => {
        expect(result).toEqual(successResult({ keys: [{ kid: 'mock_kid' }] }));
      });

      it('Makes another call to JWKS URI', () => {
        expectJwksUriToHaveBeenCalledNTimes(
          mockSendRequest,
          'mock_jwks_uri',
          2,
        );
      });
    });

    describe('Given the only previous response was from a different JWKS URI', () => {
      beforeEach(async () => {
        mockSendRequest = vi
          .fn()
          .mockResolvedValueOnce(
            buildSuccessfulJwksResponseWithKeyIdsAndMaxAge(
              ['mock_kid'],
              serverDefinedMaxAgeInSeconds,
            ),
          )
          .mockResolvedValueOnce(
            buildSuccessfulJwksResponseWithKeyIdsAndMaxAge(
              ['mock_kid'],
              serverDefinedMaxAgeInSeconds,
            ),
          );
        dependencies.sendRequest = mockSendRequest;

        inMemoryJwksCache = new InMemoryJwksCache(dependencies);
        await inMemoryJwksCache.getJwks('mock_jwks_uri');
        result = await inMemoryJwksCache.getJwks('mock_other_jwks_uri');
      });

      it('Returns success with keys', () => {
        expect(result).toEqual(successResult({ keys: [{ kid: 'mock_kid' }] }));
      });

      it('Calls both JWKS URIs', () => {
        expectJwksUriToHaveBeenCalledNTimes(
          mockSendRequest,
          'mock_jwks_uri',
          1,
        );
        expectJwksUriToHaveBeenCalledNTimes(
          mockSendRequest,
          'mock_other_jwks_uri',
          1,
        );
      });
    });

    describe('Cache expiry', () => {
      describe('Given server-defined max-age returned from previous response was less than maximum cache duration', () => {
        describe('Given server-defined max-age has elapsed', () => {
          beforeEach(async () => {
            inMemoryJwksCache = new InMemoryJwksCache(dependencies);
            await inMemoryJwksCache.getJwks('mock_jwks_uri');
            vi.setSystemTime(
              NOW_IN_MILLISECONDS + serverDefinedMaxAgeInSeconds * 1000,
            );
            result = await inMemoryJwksCache.getJwks('mock_jwks_uri');
          });

          it('Returns success with keys', () => {
            expect(result).toEqual(
              successResult({ keys: [{ kid: 'mock_kid' }] }),
            );
          });

          it('Makes another call to JWKS URI', () => {
            expectJwksUriToHaveBeenCalledNTimes(
              mockSendRequest,
              'mock_jwks_uri',
              2,
            );
          });
        });

        describe('Given Age header returned from previous response, and [max age - age] has elapsed', () => {
          beforeEach(async () => {
            mockSendRequest = vi.fn().mockResolvedValue(
              successResult({
                statusCode: 200,
                body: JSON.stringify({
                  keys: [{ kid: 'mock_kid' }],
                }),
                headers: {
                  'Cache-Control': `max-age=100`,
                  Age: `50`,
                },
              }),
            );
            dependencies.sendRequest = mockSendRequest;

            inMemoryJwksCache = new InMemoryJwksCache(dependencies);
            await inMemoryJwksCache.getJwks('mock_jwks_uri');
            vi.setSystemTime(NOW_IN_MILLISECONDS + 50000);
            result = await inMemoryJwksCache.getJwks('mock_jwks_uri');
          });

          it('Returns success with keys', () => {
            expect(result).toEqual(
              successResult({ keys: [{ kid: 'mock_kid' }] }),
            );
          });

          it('Makes another call to JWKS URI', () => {
            expectJwksUriToHaveBeenCalledNTimes(
              mockSendRequest,
              'mock_jwks_uri',
              2,
            );
          });
        });

        describe('Given Age header returned from previous response, and [max age - age] < 0', () => {
          beforeEach(async () => {
            mockSendRequest = vi.fn().mockResolvedValue(
              successResult({
                statusCode: 200,
                body: JSON.stringify({
                  keys: [{ kid: 'mock_kid' }],
                }),
                headers: {
                  'Cache-Control': `max-age=100`,
                  Age: `101`,
                },
              }),
            );
            dependencies.sendRequest = mockSendRequest;

            inMemoryJwksCache = new InMemoryJwksCache(dependencies);
            await inMemoryJwksCache.getJwks('mock_jwks_uri');
            result = await inMemoryJwksCache.getJwks('mock_jwks_uri');
          });

          it('Returns success with keys', () => {
            expect(result).toEqual(
              successResult({ keys: [{ kid: 'mock_kid' }] }),
            );
          });

          it('Makes another call to JWKS URI', () => {
            expectJwksUriToHaveBeenCalledNTimes(
              mockSendRequest,
              'mock_jwks_uri',
              2,
            );
          });
        });
      });

      describe('Given server-defined max-age returned from previous response was greater than maximum cache duration', () => {
        describe('Given maximum cache duration has elapsed', () => {
          beforeEach(async () => {
            mockSendRequest = vi
              .fn()
              .mockResolvedValue(
                buildSuccessfulJwksResponseWithKeyIdsAndMaxAge(
                  ['mock_kid'],
                  2 * MAXIMUM_CACHE_DURATION_SECONDS,
                ),
              );
            dependencies.sendRequest = mockSendRequest;

            inMemoryJwksCache = new InMemoryJwksCache(dependencies);
            await inMemoryJwksCache.getJwks('mock_jwks_uri');

            vi.setSystemTime(
              NOW_IN_MILLISECONDS + MAXIMUM_CACHE_DURATION_MILLIS,
            );
            await inMemoryJwksCache.getJwks('mock_jwks_uri');
            result = await inMemoryJwksCache.getJwks('mock_jwks_uri');
          });

          it('Returns success with keys', () => {
            expect(result).toEqual(
              successResult({ keys: [{ kid: 'mock_kid' }] }),
            );
          });

          it('Makes 2 calls to JWKS URI', () => {
            expectJwksUriToHaveBeenCalledNTimes(
              mockSendRequest,
              'mock_jwks_uri',
              2,
            );
          });
        });
      });
    });

    describe('Given previous response from JWKS URI is fresh but contained a different key ID', () => {
      beforeEach(async () => {
        mockSendRequest = vi
          .fn()
          .mockResolvedValueOnce(
            buildSuccessfulJwksResponseWithKeyIdsAndMaxAge(
              ['mock_kid'],
              serverDefinedMaxAgeInSeconds,
            ),
          )
          .mockResolvedValueOnce(
            buildSuccessfulJwksResponseWithKeyIdsAndMaxAge(
              ['mock_other_kid'],
              serverDefinedMaxAgeInSeconds,
            ),
          );
        dependencies.sendRequest = mockSendRequest;

        inMemoryJwksCache = new InMemoryJwksCache(dependencies);
        await inMemoryJwksCache.getJwks('mock_jwks_uri');
        result = await inMemoryJwksCache.getJwks(
          'mock_jwks_uri',
          'mock_other_kid',
        );
      });

      it('Returns success with keys', () => {
        expect(result).toEqual(
          successResult({ keys: [{ kid: 'mock_other_kid' }] }),
        );
      });

      it('Makes another call to JWKS URI', () => {
        expectJwksUriToHaveBeenCalledNTimes(
          mockSendRequest,
          'mock_jwks_uri',
          2,
        );
      });
    });

    describe('Given previous response from JWKS URI is fresh and contained matching key ID', () => {
      beforeEach(async () => {
        inMemoryJwksCache = new InMemoryJwksCache(dependencies);
        await inMemoryJwksCache.getJwks('mock_jwks_uri');
        result = await inMemoryJwksCache.getJwks('mock_jwks_uri', 'mock_kid');
      });

      it('Returns success with keys', () => {
        expect(result).toEqual(successResult({ keys: [{ kid: 'mock_kid' }] }));
      });

      it('Does not make an additional call to JWKS URI', () => {
        expectJwksUriToHaveBeenCalledNTimes(
          mockSendRequest,
          'mock_jwks_uri',
          1,
        );
      });
    });

    describe('Given previous response from JWKS URI is fresh and no key ID is provided', () => {
      beforeEach(async () => {
        inMemoryJwksCache = new InMemoryJwksCache(dependencies);
        await inMemoryJwksCache.getJwks('mock_jwks_uri');
        result = await inMemoryJwksCache.getJwks('mock_jwks_uri');
      });

      it('Returns success with keys', () => {
        expect(result).toEqual(successResult({ keys: [{ kid: 'mock_kid' }] }));
      });

      it('Does not make additional call to JWKS URI', () => {
        expectJwksUriToHaveBeenCalledNTimes(
          mockSendRequest,
          'mock_jwks_uri',
          1,
        );
      });
    });
  });
});

function expectJwksUriToHaveBeenCalledNTimes(
  httpRequestMock: Mock<ISendHttpRequest>,
  jwksUri: string,
  numberOfCalls: number,
): void {
  const matchingCalls = httpRequestMock.mock.calls.filter((call) => {
    return call[0].url === jwksUri && call[0].method === 'GET';
  });
  expect(matchingCalls.length).toEqual(numberOfCalls);
}

function buildSuccessfulJwksResponseWithKeyIdsAndMaxAge(
  keyIds: string[],
  maxAgeSeconds: number,
): SuccessWithValue<SuccessfulHttpResponse> {
  return successResult({
    statusCode: 200,
    body: JSON.stringify({
      keys: keyIds.map((keyId) => ({ kid: keyId })),
    }),
    headers: {
      'Cache-Control': `max-age=${maxAgeSeconds}`,
    },
  });
}
