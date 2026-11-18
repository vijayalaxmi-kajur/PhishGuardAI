export interface ScanResult {
  success: boolean;
  url: string;
  domain?: string;
  verdict: string;
  standardized_verdict: string;
  risk_level: "low" | "medium" | "high" | "critical" | "unknown";
  phishing_probability: number;
  confidence_percent: number;
  latency_ms?: number;
  cached?: boolean;
  explanation?: string[];
  warnings?: string[];
  threat_intelligence?: Record<string, any>;
  structural_indicators?: Record<string, any>;
  scanned_at?: string;
  error?: string;
}

export interface ClientOptions {
  apiKey?: string;
  baseUrl?: string;
  timeout?: number;
  sessionToken?: string;
}

export interface ScanOptions {
  checkPresence?: boolean;
}

export interface BatchScanOptions {
  concurrency?: number;
  checkPresence?: boolean;
}

export interface ApiKey {
  id: number;
  key_prefix: string;
  label: string;
  is_live: boolean;
  created_at: string;
  last_used_at?: string;
  revoked: boolean;
}

export class PhishGuardError extends Error {
  statusCode?: number | null;
  responseBody: Record<string, any>;
}

export class AuthenticationError extends PhishGuardError {}
export class RateLimitError extends PhishGuardError {}
export class InvalidURLError extends PhishGuardError {}
export class APIConnectionError extends PhishGuardError {}

export class PhishGuardClient {
  constructor(options?: ClientOptions);
  scan(url: string, options?: ScanOptions): Promise<ScanResult>;
  isPhishing(url: string): Promise<boolean>;
  getRiskScore(url: string): Promise<number>;
  batchScan(urls: string[], options?: BatchScanOptions): Promise<ScanResult[]>;
  getUsage(): Promise<Record<string, any>>;
  listKeys(): Promise<ApiKey[]>;
  createKey(params?: { label?: string; isLive?: boolean }): Promise<ApiKey>;
  revokeKey(keyId: number): Promise<boolean>;
}

