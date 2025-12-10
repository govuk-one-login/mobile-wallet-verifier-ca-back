export interface IssueReaderCertRequest {
  platform: 'ios' | 'android';
  nonce: string;
  csrPem: string;
  appAttest?: {
    keyId: string;
    attestationObject: string;
    clientDataJSON: string;
  };
  keyAttestationChain?: string[];
  playIntegrityToken?: string;
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
