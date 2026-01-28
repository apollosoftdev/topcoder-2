/**
 * Backend API client for communicating with the guardrails service.
 */

export interface AnalysisConfig {
  enforcement_mode: 'advisory' | 'warning' | 'blocking';
  rule_packs: string[];
  custom_rules?: string;
  ai_review_enabled: boolean;
  copilot_detection_enabled: boolean;
}

export interface AnalyzeRequest {
  repository: string;
  pull_request_number?: number;
  commit_sha?: string;
  diff: string;
  files: string[];
  config: AnalysisConfig;
}

export interface Violation {
  type: string;
  severity: string;
  rule: string;
  file: string;
  line: number;
  column: number;
  message: string;
  suggestion: string;
  code_snippet: string;
  cwe?: string;
  owasp?: string;
}

export interface AISecurityIssue {
  severity: string;
  title: string;
  description: string;
  file?: string;
  line?: number;
  cwe?: string;
  owasp?: string;
  recommendation: string;
}

export interface AICodeQualityIssue {
  severity: string;
  title: string;
  description: string;
  file?: string;
  line?: number;
  recommendation: string;
}

export interface AIReview {
  summary: string;
  security_issues: AISecurityIssue[];
  code_quality_issues: AICodeQualityIssue[];
  recommendations: string[];
  copilot_indicators: string[];
  risk_score: number;
}

export interface CopilotDetection {
  detected: boolean;
  confidence: number;
  indicators: string[];
}

export interface LicenseInfo {
  count: number;
  severity: string;
  files: string[];
}

export interface LicenseSummary {
  total_license_violations: number;
  total_ip_violations: number;
  licenses_found: Record<string, LicenseInfo>;
  has_restricted_licenses: boolean;
  has_copyleft_licenses: boolean;
}

export interface AnalysisResult {
  request_id: string;
  repository: string;
  pull_request_number?: number;
  commit_sha?: string;
  violations: Violation[];
  ai_review?: AIReview;
  copilot_detection?: CopilotDetection;
  license_summary?: LicenseSummary;
  enforcement_action: string;
  should_block: boolean;
  ai_code_detected: boolean;
  stricter_enforcement_applied: boolean;
  summary: string;
  analyzed_at: string;
}

export interface OverrideRequest {
  repository: string;
  pull_request_number: number;
  request_id: string;
  overridden_by: string;
  reason: string;
  violations_count: number;
}

export interface OverrideResult {
  success: boolean;
  override_id?: number;
  message: string;
  repository: string;
  pull_request_number: number;
  overridden_by: string;
  created_at?: string;
}

export class ApiClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly allowedBaseUrl: string;

  constructor() {
    // Base URL is configured from environment, not user input (trusted source)
    this.baseUrl = process.env.BACKEND_API_URL || 'http://localhost:8000';
    this.allowedBaseUrl = this.baseUrl;
    this.apiKey = process.env.BACKEND_API_KEY;
    // Default timeout of 30 seconds for API calls
    this.timeoutMs = parseInt(process.env.BACKEND_API_TIMEOUT || '30000', 10);
  }

  /**
   * Builds a safe URL by ensuring it stays within the trusted base URL.
   * This prevents SSRF attacks by validating the constructed URL.
   */
  private buildSafeUrl(path: string): string {
    // Construct URL using the trusted base URL
    const url = new URL(path, this.allowedBaseUrl);

    // Validate the URL stays within the allowed base
    if (!url.href.startsWith(this.allowedBaseUrl)) {
      throw new Error('URL validation failed: constructed URL is outside allowed base');
    }

    return url.href;
  }

  async analyze(request: AnalyzeRequest): Promise<AnalysisResult> {
    const url = `${this.baseUrl}/api/v1/analyze`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`API request failed: ${response.status} ${error}`);
      }

      return response.json() as Promise<AnalysisResult>;
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`API request timed out after ${this.timeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async getHealth(): Promise<{ status: string; version: string }> {
    const url = `${this.baseUrl}/api/v1/health`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, { signal: controller.signal });

      if (!response.ok) {
        throw new Error(`Health check failed: ${response.status}`);
      }

      return response.json() as Promise<{ status: string; version: string }>;
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`Health check timed out after ${this.timeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async requestOverride(request: OverrideRequest): Promise<OverrideResult> {
    const url = `${this.baseUrl}/api/v1/override`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Override request failed: ${response.status} ${error}`);
      }

      return response.json() as Promise<OverrideResult>;
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`Override request timed out after ${this.timeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async checkOverride(
    repository: string,
    pullRequestNumber: number
  ): Promise<{ has_override: boolean; override?: unknown }> {
    // Validate inputs to prevent path traversal
    if (!repository || typeof repository !== 'string') {
      throw new Error('Invalid repository parameter');
    }
    if (!Number.isInteger(pullRequestNumber) || pullRequestNumber < 0) {
      throw new Error('Invalid pullRequestNumber parameter');
    }

    // Build URL safely using trusted base URL
    const path = `/api/v1/override/${encodeURIComponent(repository)}/pr/${pullRequestNumber}`;
    const url = this.buildSafeUrl(path);

    const headers: Record<string, string> = {};

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      // URL is validated via buildSafeUrl() to prevent SSRF - base URL is from trusted env config
      // nosemgrep: gitlab.nodejs_scan.javascript-ssrf-rule-node_ssrf
      const response = await fetch(url, { headers, signal: controller.signal });

      if (!response.ok) {
        throw new Error(`Override check failed: ${response.status}`);
      }

      return response.json() as Promise<{ has_override: boolean; override?: unknown }>;
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`Override check timed out after ${this.timeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
