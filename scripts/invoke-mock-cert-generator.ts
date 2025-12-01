#!/usr/bin/env tsx

import { handler } from '../src/lambdas/generate-mock-issue-cert/handler.js';
import { APIGatewayProxyEvent } from 'aws-lambda';

async function invokeMockCertGenerator() {
  console.log('Invoking mock certificate generator...');

  const mockEvent: APIGatewayProxyEvent = {
    httpMethod: 'GET',
    path: '/generate-mock-cert',
    headers: {},
    multiValueHeaders: {},
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    pathParameters: null,
    stageVariables: null,
    requestContext: {
      accountId: 'test',
      apiId: 'test',
      httpMethod: 'GET',
      identity: {
        accessKey: null,
        accountId: null,
        apiKey: null,
        apiKeyId: null,
        caller: null,
        cognitoAuthenticationProvider: null,
        cognitoAuthenticationType: null,
        cognitoIdentityId: null,
        cognitoIdentityPoolId: null,
        principalOrgId: null,
        sourceIp: '127.0.0.1',
        user: null,
        userAgent: 'test',
        userArn: null,
        clientCert: null
      },
      path: '/generate-mock-cert',
      stage: 'test',
      requestId: 'test-request-id',
      requestTime: new Date().toISOString(),
      requestTimeEpoch: Date.now(),
      resourceId: 'test',
      resourcePath: '/generate-mock-cert',
      protocol: 'HTTP/1.1',
      authorizer: null
    },
    resource: '/generate-mock-cert',
    body: null,
    isBase64Encoded: false
  };

  try {
    const result = await handler(mockEvent);
    
    console.log('✅ Mock certificate generator invoked successfully');
    console.log('Status Code:', result.statusCode);
    console.log('Response Body:');
    console.log(JSON.stringify(JSON.parse(result.body), null, 2));
    
  } catch (error) {
    console.error('❌ Error invoking mock certificate generator:', error);
    process.exit(1);
  }
}

invokeMockCertGenerator();