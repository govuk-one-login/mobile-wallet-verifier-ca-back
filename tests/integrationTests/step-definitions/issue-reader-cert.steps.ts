import { Before, Given, Then, When } from '@cucumber/cucumber';
import assert from 'node:assert/strict';
import {
  requestIssueReaderCert,
  requestMockIssueReaderCertRequest,
  MockIssueReaderCertRequest,
  createUntrustedFirebaseAppCheckJwt,
} from '../utils/integration-test-helpers.ts';
import type { HttpResponseSnapshot } from '../utils/api-instance.ts';

let mockRequest: MockIssueReaderCertRequest | undefined;
let response: HttpResponseSnapshot | undefined;
const LAMBDA_TIMEOUT = 60 * 15000;

Before(() => {
  mockRequest = undefined;
  response = undefined;
});

Given(
  'I generate an issue reader cert request without an App Check JWT',
  async () => {
    const validMockRequest = await requestMockIssueReaderCertRequest();
    mockRequest = {
      ...validMockRequest,
      headers: {
        'X-Firebase-AppCheck': '',
      },
    };
  },
);

Given(
  'I generate an issue reader cert request with an App Check JWT signed by an untrusted key pair',
  async () => {
    const validMockRequest = await requestMockIssueReaderCertRequest();
    const untrustedJwt = await createUntrustedFirebaseAppCheckJwt(
      validMockRequest.headers['X-Firebase-AppCheck'],
    );

    mockRequest = {
      ...validMockRequest,
      headers: {
        'X-Firebase-AppCheck': untrustedJwt,
      },
    };
  },
);

Given('I generate a valid issue reader cert request', async () => {
  mockRequest = await requestMockIssueReaderCertRequest();
});

When(
  'I submit the request to the issue reader cert endpoint',
  { timeout: LAMBDA_TIMEOUT },
  async () => {
    assert.ok(
      mockRequest,
      'A mock issue reader certificate request must be generated first',
    );

    response = await requestIssueReaderCert(mockRequest);
  },
);

Then('the issue reader cert endpoint returns a 401 response', () => {
  assert.ok(
    response,
    'The issue reader cert endpoint must be called before asserting on the response',
  );

  assert.equal(
    response.status,
    401,
    `Unexpected response from ${response.url}: ${response.body}`,
  );
});

Then('the response body indicates a missing App Check token', () => {
  assert.ok(
    response,
    'The issue reader cert endpoint must be called before asserting on the response',
  );

  assert.ok(response.headers['content-type']?.includes('application/json'));

  const parsedBody = JSON.parse(response.body);
  assert.equal(parsedBody.code, 'unauthorized');
  assert.equal(
    parsedBody.message,
    'X-Firebase-AppCheck header missing from event',
  );
});

Then('the response body indicates an invalid App Check token', () => {
  assert.ok(
    response,
    'The issue reader cert endpoint must be called before asserting on the response',
  );

  assert.ok(response.headers['content-type']?.includes('application/json'));

  const parsedBody = JSON.parse(response.body);
  assert.equal(parsedBody.code, 'unauthorized');
  assert.equal(parsedBody.message, 'App Check JWT signature is invalid');
});

Then('the issue reader cert endpoint returns a 200 OK response', () => {
  assert.ok(
    response,
    'The issue reader cert endpoint must be called before asserting on the response',
  );

  assert.equal(
    response.status,
    200,
    `Unexpected response from ${response.url}: ${response.body}`,
  );

  const parsedBody = JSON.parse(response.body);

  assert.ok(
    typeof parsedBody.certChain === 'string',
    'certChain should be a string',
  );
  assert.ok(parsedBody.certChain.length > 0, 'certChain should not be empty');
  assert.ok(response.headers['content-type']?.includes('application/json'));
  assert.ok(response.headers['x-request-id']?.trim());
});
