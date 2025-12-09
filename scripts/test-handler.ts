#!/usr/bin/env node

// Set environment for testing
process.env.ALLOW_TEST_TOKENS = 'true';
process.env.EXPECTED_ANDROID_PACKAGE_NAME = 'org.multipaz.identityreader';

import { handler } from '../src/lambdas/issue-reader-cert-service/handler';
import type { APIGatewayProxyEvent, Context } from 'aws-lambda';

const mockContext: Context = {
  callbackWaitsForEmptyEventLoop: false,
  functionName: 'test-function',
  functionVersion: '1',
  invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
  memoryLimitInMB: '128',
  awsRequestId: 'test-request-id',
  logGroupName: '/aws/lambda/test-function',
  logStreamName: '2023/01/01/[$LATEST]test-stream',
  getRemainingTimeInMillis: () => 30000,
  done: () => {},
  fail: () => {},
  succeed: () => {},
};

const payload = {
  nonce: '1a9b9e3a-435b-480b-abb6-7ae6f8e54dc7',
  csrPem:
    '-----BEGIN CERTIFICATE REQUEST-----\nMIHyMIGaAgEAMDgxCzAJBgNVBAYTAlVLMQwwCgYDVQQKEwNHRFMxGzAZBgNVBAMT\nEkFuZHJvaWQgRGV2aWNlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDlt\n4vSyJY/RnL8bC5bHhhfxDZ3m69UBx/IADlbZhZ4nzImHuzVJsck2LsPefb91g6hc\nhq81PZei3c7qN2rfJIqgADAKBggqhkjOPQQDAgNHADBEAiBB/OcSic76VdMJuaZZ\nDb7APgiSkx8KMGbrqo4PgDy25AIgJH+tVfzC4B8R0ZNCuTpEJlJx9DVW0I1X24dI\nKnLJRN8=\n-----END CERTIFICATE REQUEST-----',
  keyAttestationChain: [
    'MIICHjCCAcOgAwIBAgIBAzAKBggqhkjOPQQDAjBwMTowOAYDVQQDEzFUZXN0IEFuZHJvaWQgSGFyZHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlIENBMRAwDgYDVQQLEwdBbmRyb2lkMRMwEQYDVQQKEwpHb29nbGUgSW5jMQswCQYDVQQGEwJVUzAeFw0yNTEyMDkxMTAyMDZaFw0yNjEyMDkxMTAyMDZaMFcxITAfBgNVBAMTGFRlc3QgQW5kcm9pZCBBdHRlc3RhdGlvbjEQMA4GA1UECxMHQW5kcm9pZDETMBEGA1UEChMKR29vZ2xlIEluYzELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5beL0siWP0Zy/GwuWx4YX8Q2d5uvVAcfyAA5W2YWeJ8yJh7s1SbHJNi7D3n2/dYOoXIavNT2Xot3O6jdq3ySKo2cwZTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIFoDBIBgorBgEEAdZ5AgERBDowOAIBBAoBAQIBBAoBAQQkMWE5YjllM2EtNDM1Yi00ODBiLWFiYjYtN2FlNmY4ZTU0ZGM3BAAwADAAMAoGCCqGSM49BAMCA0kAMEYCIQDYEM2eKkTI/YvQeXXPlk+EohycP65/MYLLtuWzdp92qgIhANmgalVBfLXhZzug7XxnkAQ9PYvjh7Tyui7e6r5ipeo/',
    'MIIB7TCCAZOgAwIBAgIBAjAKBggqhkjOPQQDAjBoMTIwMAYDVQQDEylUZXN0IEFuZHJvaWQgSGFyZHdhcmUgQXR0ZXN0YXRpb24gUm9vdCBDQTEQMA4GA1UECxMHQW5kcm9pZDETMBEGA1UEChMKR29vZ2xlIEluYzELMAkGA1UEBhMCVVMwHhcNMjUxMjA5MTEwMjA2WhcNMzAxMjA4MTEwMjA2WjBwMTowOAYDVQQDEzFUZXN0IEFuZHJvaWQgSGFyZHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlIENBMRAwDgYDVQQLEwdBbmRyb2lkMRMwEQYDVQQKEwpHb29nbGUgSW5jMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM6emMbqioK0RMv39DZJLdo7UDttgpedVFexDymZotevfF5lcwAGkkaUpkKCXcsoqzkdAKyW0WuNXvB4rC3uwm6jJjAkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIH9LH+r/EJjU+SBlx7qaCoeNb41G4xm4770Lm8VBWLP/AiEA/nxskNltiUwG+J/Tlud5KybwiKx35RQu6X+vCx5G+2k=',
  ],
  playIntegrityToken:
    'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFuZHJvaWQtcGxheS1pbnRlZ3JpdHkta2V5cy05In0.eyJyZXF1ZXN0RGV0YWlscyI6eyJyZXF1ZXN0UGFja2FnZU5hbWUiOiJvcmcubXVsdGlwYXouaWRlbnRpdHlyZWFkZXIiLCJ0aW1lc3RhbXBNaWxsaXMiOiIxNzY1Mjc4MTI0ODMwIiwibm9uY2UiOiIxYTliOWUzYS00MzViLTQ4MGItYWJiNi03YWU2ZjhlNTRkYzcifSwiYXBwSW50ZWdyaXR5Ijp7ImFwcFJlY29nbml0aW9uVmVyZGljdCI6IlBMQVlfUkVDT0dOSVpFRCIsInBhY2thZ2VOYW1lIjoib3JnLm11bHRpcGF6LmlkZW50aXR5cmVhZGVyIiwiY2VydGlmaWNhdGVTaGEyNTZEaWdlc3QiOlsiYWJjMTIzIl0sInZlcnNpb25Db2RlIjoiMSJ9LCJkZXZpY2VJbnRlZ3JpdHkiOnsiZGV2aWNlUmVjb2duaXRpb25WZXJkaWN0IjpbIk1FRVRTX0RFVklDRV9JTlRFR1JJVFkiXX0sImFjY291bnREZXRhaWxzIjp7ImFwcExpY2Vuc2luZ1ZlcmRpY3QiOiJMSUNFTlNFRCJ9fQ.MEQCIAd85G2PWU6_wqr7USz34aHHL7Rz9380LER95Ahp8ZYyAiBP84I8K10CDVxIR62UfDnVAfwnWbGqbZEqDZY4bGqNFQ',
  platform: 'android',
};
async function testAndroidRequest() {
  console.log('Testing Android request...');

  const event: APIGatewayProxyEvent = {
    httpMethod: 'POST',
    path: '/issue-reader-cert',
    body: JSON.stringify(payload),
    //     body: JSON.stringify({
    //         "nonce": "f18d7ad9-1a0f-4b3f-9235-db6ff194d928",
    //         "platform": "android",
    //         "keyAttestationChain":  [
    //                 "MIIDPzCCAiegAwIBAgIURvykRtM3wn2g6WwsaZdR7jp2hLowDQYJKoZIhvcNAQELBQAwIzEhMB8GA1UEAwwYVGVzdCBBbmRyb2lkIEF0dGVzdGF0aW9uMB4XDTI1MTEyODE1MzYwNVoXDTI2MTEyODE1MzYwNVowIzEhMB8GA1UEAwwYVGVzdCBBbmRyb2lkIEF0dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzBQ3p8pl1IcWpo1SMG5kK/kskwqMY5VawcWzNKByKy15hEKDn635IGlB6jlG0wKqZrzNil8Z77HqeqIfqQCsAl/5DYKYaWwx7SjQu6cpibUH8fVm8azXw+lSo1dbSUuivh48zrQmVCaz40BLTCVJRLBNoozaMoeLg5mMco4MKA6lF5g2F96txJ48q4m6oQ1BgOhBublMtiZvI13XgaXzXcvu1B5N3U6hszBMd616CBx3SOdnCzn8J1yyAqlDwZ5QNTEc1hprxUTcV8/ICKYWw0bGlW15s+rmsnSxRzcTzi9W4ahVMv7r+wOqSJ1ELmsCh/gj879ES9M7pNMIdQkTywIDAQABo2swaTBIBgorBgEEAdZ5AgERBDowOAIBBAoBAQIBBAoBAQQkZjE4ZDdhZDktMWEwZi00YjNmLTkyMzUtZGI2ZmYxOTRkOTI4BAAwADAAMB0GA1UdDgQWBBQ8nHU/QT+LFzy0R03E0Kpt8bHE5jANBgkqhkiG9w0BAQsFAAOCAQEAF+h0y+Jxgo47k+twugxHf3vW6L5kj0aIZw+6P5Q90vbzb2vCYINOPB3TC2ileftMVQuPT2nY5JaRSkf+aduCn4g5RDePi842EH9CpxtjxQssXV4/UMHjgss6vqedPcnoMVPrtpCOIkmD9Eagse5ioBqml+OoKrHqmpeHdJ7WFAO+q8OnunIIe345Lm5nq5NY5jOv9bqKX7p3A2pO2kjSMgTEwKSaNADnOpv3/WGcpKes195/aDw3MjZTL8JL2bxZ54xw1sx+8cGox3hKcqt5AZdE2gpyp2oWnwHYSx9K7aThjRwhi0gDAqZ8g5quNOORfVj5nyJSR9+bjho2cfXasQ==",
    //                 "MIIB4TCCAYigAwIBAgIRAPv5X5GO2UBf5j1v+C59ED4wCgYIKoZIzj0EAwIwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMB4XDTI1MTExOTE1MjIzMloXDTI1MTIxNTA4NDkwOFowOTEMMAoGA1UEChMDVEVFMSkwJwYDVQQDEyBmYmY5NWY5MThlZDk0MDVmZTYzZDZmZjgyZTdkMTAzZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABN+jUH32kqwQBCDsS/Yf7tn3KTQw6S6rytg5p8TcXyTeDaC1bT3QIRK67Uap8fk42HvLHnE6Ej9KZ9FAMWRFunCjgYAwfjAdBgNVHQ4EFgQUn2bHaJxfPamGN1KBweMJV7NYn0gwHwYDVR0jBBgwFoAUz3lFLzo+fu4eMzlBcfxcaj52Z/wwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwGwYKKwYBBAHWeQIBHgQNogEIA2htb3Rvcm9sYTAKBggqhkjOPQQDAgNHADBEAiBpeIMwbSkeXitiVbOQ7GALjZrHWhuwDyVnESTw5Xw91QIgCsZ/DJcFXYtJKMvxAxOpOGxTaokd1fjbn2SBvNUJMZ0",
    //                 "MIIB1zCCAV2gAwIBAgIUAM3jzJvd13YksVVX6rFS5JLuiEgwCgYIKoZIzj0EAwMwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMB4XDTI1MTEyMDE3MzkyM1oXDTI2MDEyOTE3MzkyMlowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcRkf7lOdWbxToXEbTu0mTw7zP6WInKqmC1DosoSuZS7ZOo6MoRhsWBQrFhBlssHpvQfQ6Z05VkcKWGDIbP8pjqNjMGEwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFM95RS86Pn7uHjM5QXH8XGo+dmf8MB8GA1UdIwQYMBaAFLv4Nq2Jrmzi5Z6U8NWy19J65HxBMAoGCCqGSM49BAMDA2gAMGUCMQC5yPPVc6QwTtaonx9bJLR0VDOLFf79jszdg1dgvhKR2ecxu3lkiFHAX6nPoYhVf28CMCUAv3Ayl9837LgmhPb6a4lLZ8j7+Sn9HZZnXzxQg1C3mWSK6rBxYLKhZlbu4ROUJQ",
    //                 "MIIDgDCCAWigAwIBAgIKA4gmZ2BliZaGDTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIyMDEyNjIyNDc1MloXDTM3MDEyMjIyNDc1MlowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuppxbZvJgwNXXe6qQKidXqUt1ooT8M6Q+ysWIwpduM2EalST8v/Cy2JN10aqTfUSThJha/oCtG+F9TUUviOch6RahrpjVyBdhopM9MFDlCfkiCkPCPGu2ODMj7O/bKnko2YwZDAdBgNVHQ4EFgQUu/g2rYmubOLlnpTw1bLX0nrkfEEwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwEgYDVR0TAQH/BAgwBgEB/wIBAjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAIFxUiFHYfObqrJM0eeXI+kZFT57wBplhq+TEjd+78nIWbKvKGUFlvt7IuXHzZ7YJdtSDs7lFtCsxXdrWEmLckxRDCRcth3Eb1leFespS35NAOd0Hekg8vy2G31OWAe567l6NdLjqytukcF4KAzHIRxoFivN+tlkEJmg7EQw9D2wPq4KpBtug4oJE53R9bLCT5wSVj63hlzEY3hC0NoSAtp0kdthow86UFVzLqxEjR2B1MPCMlyIfoGyBgkyAWhd2gWN6pVeQ8RZoO5gfPmQuCsn8m9kv/dclFMWLaOawgS4kyAn9iRi2yYjEAI0VVi7u3XDgBVnowtYAn4gma5q4BdXgbWbUTaMVVVZsepXKUpDpKzEfss6Iw0zx2Gql75zRDsgyuDyNUDzutvDMw8mgJmFkWjlkqkVM2diDZydzmgi8br2sJTLdG4lUwvedIaLgjnIDEG1J8/5xcPVQJFgRf3m5XEZB4hjG3We/49p+JRVQSpE1+QzG0raYpdNsxBUO+41diQo7qC7S8w2J+TMeGdpKGjCIzKjUDAy2+gOmZdZacanFN/03SydbKVHV0b/NYRWMa4VaZbomKON38IH2ep8pdj++nmSIXeWpQE8LnMEdnUFjvDzp0f0ELSXVW2+5xbl+fcqWgmOupmU4+bxNJLtknLo49Bg5w9jNn7T7rkF",
    //                 "MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83Uh6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vAD32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx+tWUDqG8At2JHA"
    //             ],
    //         "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nMIHvMIGXAgEAMDUxGDAWBgNVBAMMD0FuZHJvaWQgUmVxdWVzdDEMMAoGA1UECgwD\nR0RTMQswCQYDVQQGEwJVSzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB2Bv0qW\ntBWS+4FxakVFzrPCgWmSDQzj0GK0eZHCCLnDM2WdWmt6PKp5g0XfbduXjwZ5BBSd\nxEZI9Renl0tpQXigADAKBggqhkjOPQQDAgNHADBEAiDAl21OaArIY0iuhBjWCCAG\nG9xq0Emod2hNkD5WGal0jwIg2w/5CnultuyzJ0baHaN3hqyQ1X3TH3VT6Rcc6lk1\nMTg=\n-----END CERTIFICATE REQUEST-----\n ",
    //         "playIntegrityToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZXF1ZXN0RGV0YWlscyI6eyJyZXF1ZXN0UGFja2FnZU5hbWUiOiJvcmcubXVsdGlwYXouaWRlbnRpdHlyZWFkZXIiLCJ0aW1lc3RhbXBNaWxsaXMiOiIxNzY0MjUzNDA0MDMyIiwibm9uY2UiOiJhLVZqc0hRMVk5eWZsUkhzTlJvRUNhS2YyVllVOE1BVVQ5b1ViN0FDUU9zIn0sImFwcEludGVncml0eSI6eyJhcHBSZWNvZ25pdGlvblZlcmRpY3QiOiJQTEFZX1JFQ09HTklaRUQiLCJwYWNrYWdlTmFtZSI6Im9yZy5tdWx0aXBhei5pZGVudGl0eXJlYWRlciIsImNlcnRpZmljYXRlU2hhMjU2RGlnZXN0IjpbImFiYzEyMyJdLCJ2ZXJzaW9uQ29kZSI6IjEifSwiZGV2aWNlSW50ZWdyaXR5Ijp7ImRldmljZVJlY29nbml0aW9uVmVyZGljdCI6WyJNRUVUU19ERVZJQ0VfSU5URUdSSVRZIl19LCJhY2NvdW50RGV0YWlscyI6eyJhcHBMaWNlbnNpbmdWZXJkaWN0IjoiTElDRU5TRUQifX0.test-signature"
    // }),
    headers: {},
    multiValueHeaders: {},
    isBase64Encoded: false,
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {} as any,
    resource: '',
  };

  try {
    const result = await handler(event, mockContext);
    console.log('Response Status:', result.statusCode);
    console.log('Response Body:', JSON.parse(result.body));
  } catch (error) {
    console.error('Error:', error);
  }
}

async function testIOSRequest() {
  console.log('\nTesting iOS request...');

  const event: APIGatewayProxyEvent = {
    httpMethod: 'POST',
    path: '/issue-reader-cert',
    body: JSON.stringify({
      platform: 'ios',
      nonce: 'Z3VPeG5iY3lFbUtMZ2d0a1ZtT0pnZw',
      csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----',
      appAttest: {
        keyId: 'Xzy1AbCdEfGhIjKlMnOp',
        attestationObject: 'o2NmbXRkYXR0ZXN0YXR0...',
        clientDataJSON: 'eyJjaGFsbGVuZ2UiOiAiZ3VP...',
      },
    }),
    headers: {},
    multiValueHeaders: {},
    isBase64Encoded: false,
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {} as any,
    resource: '',
  };

  try {
    const result = await handler(event, mockContext);
    console.log('Response Status:', result.statusCode);
    console.log('Response Body:', JSON.parse(result.body));
  } catch (error) {
    console.error('Error:', error);
  }
}

async function main() {
  await testAndroidRequest();
  // await testIOSRequest();
}

main().catch(console.error);
