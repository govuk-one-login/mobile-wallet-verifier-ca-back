import { Before, Given, Then, When } from '@cucumber/cucumber';
import assert from 'node:assert/strict';
import {
  requestIssueReaderCert,
  requestMockIssueReaderCertRequest,
  IssueReaderCertRequest,
} from '../utils/integration-test-helpers.ts';
import type { HttpResponseSnapshot } from '../utils/api-instance.ts';

let mockRequest: IssueReaderCertRequest | undefined;
let response: HttpResponseSnapshot | undefined;
const LAMBDA_TIMEOUT = 60 * 15000;

Before(() => {
  mockRequest = undefined;
  response = undefined;
});

Given(
  'I generate an issue reader cert request without an App Check JWT and a valid CSR',
  async () => {
    const validMockRequest = await requestMockIssueReaderCertRequest();
    // Send only the valid CSR body with no X-Firebase-AppCheck header. App
    // Check JWT validation is disabled via feature flag in all environments for
    // this phase, so the request succeeds without the header (200).
    mockRequest = { body: validMockRequest.body };
  },
);

Given('I generate an issue reader cert request without a CSR', () => {
  // Send a body with no csrPem to exercise CSR validation. App Check JWT
  // validation is disabled via feature flag in all environments for this
  // phase, so the request reaches CSR validation and is rejected with a 400.
  mockRequest = { body: {} };
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

Then('the issue reader cert endpoint returns a 400 response', () => {
  assert.ok(
    response,
    'The issue reader cert endpoint must be called before asserting on the response',
  );

  assert.equal(
    response.status,
    400,
    `Unexpected response from ${response.url}: ${response.body}`,
  );
});

Then('the response body indicates a missing CSR', () => {
  assert.ok(
    response,
    'The issue reader cert endpoint must be called before asserting on the response',
  );

  assert.ok(response.headers['content-type']?.includes('application/json'));

  const parsedBody = JSON.parse(response.body);
  assert.equal(parsedBody.code, 'bad_request');
  assert.equal(parsedBody.message, 'Event body missing csrPem');
});
