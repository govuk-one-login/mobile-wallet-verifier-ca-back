import { Before, Given, Then, When } from '@cucumber/cucumber';
import assert from 'node:assert/strict';
import {
  requestIssueReaderCert,
  requestMockIssueReaderCertRequest,
  MockIssueReaderCertRequest
} from '../utils/integration-test-helpers.ts';
import type { HttpResponseSnapshot } from '../utils/api-instance.ts';

let mockRequest: MockIssueReaderCertRequest | undefined;
let response: HttpResponseSnapshot | undefined;

Before(() => {
  mockRequest = undefined;
  response = undefined;
});

Given('I generate a valid mock issue reader certificate request', async () => {
  mockRequest = await requestMockIssueReaderCertRequest();
});

When(
  'I submit the mock issue reader certificate request to the issue reader cert endpoint',
  async () => {
    if (mockRequest === undefined) {
      throw new Error(
        'A mock issue reader certificate request must be generated first',
      );
    }

    response = await requestIssueReaderCert(mockRequest);
  },
);

Then('the issue reader cert endpoint returns a 200 OK response', () => {
  if (response === undefined) {
    throw new Error(
      'The issue reader cert endpoint must be called before asserting the response',
    );
  }

  assert.equal(
    response.status,
    200,
    `Unexpected response from ${response.url}: ${response.body}`,
  );
  assert.equal(response.body, 'OK');
  assert.ok(response.headers['content-type']?.includes('application/json'));
  assert.ok(response.headers['x-request-id']?.trim());
});
