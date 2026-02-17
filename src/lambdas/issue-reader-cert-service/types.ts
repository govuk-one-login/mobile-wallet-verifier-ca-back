export interface IssueReaderCertRequest {
  csrPem: string;
}

export interface MockIssueReaderCertRequest {
  headers: {
    'X-Firebase-AppCheck': string;
  };
  body: IssueReaderCertRequest;
}

export interface IssueReaderCertResponse {
  readerId: string;
  certChain: {
    leaf: string;
    intermediate?: string;
  };
  profile: string;
  notBefore: string;
  notAfter: string;
}

export interface ErrorResponse {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface AttestationResult {
  valid: boolean;
  code?: string;
  message?: string;
}
