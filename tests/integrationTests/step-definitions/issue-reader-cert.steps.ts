import { Before, Given, Then, When } from '@cucumber/cucumber';
import assert from 'node:assert/strict';
import {
  requestIssueReaderCert,
  requestMockIssueReaderCertRequest,
  MockIssueReaderCertRequest,
} from '../utils/integration-test-helpers.ts';
import type { HttpResponseSnapshot } from '../utils/api-instance.ts';

let mockRequest: MockIssueReaderCertRequest | undefined;
let response: HttpResponseSnapshot | undefined;
let body;

Before(() => {
  mockRequest = undefined;
  response = undefined;
});

Given('I generate a valid issue reader cert request', async () => {
  mockRequest = await requestMockIssueReaderCertRequest();
});

When('I submit the request to the issue reader cert endpoint', async () => {
  assert.ok(
    mockRequest,
    'A mock issue reader certificate request must be generated first',
  );

  response = await requestIssueReaderCert(mockRequest);
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

  body = JSON.parse(response.body);

  assert.ok(typeof body.certChain === 'string', 'certChain should be a string');
  assert.ok(body.certChain.length > 0, 'certChain should not be empty');
  assert.ok(response.headers['content-type']?.includes('application/json'));
  assert.ok(response.headers['x-request-id']?.trim());
});
