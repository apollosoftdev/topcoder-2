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

export interface AnalysisResult {
  request_id: string;
  repository: string;
  pull_request_number?: number;
  commit_sha?: string;
  violations: Violation[];
  ai_review?: AIReview;
  copilot_detection?: CopilotDetection;
  enforcement_action: string;
  should_block: boolean;
  summary: string;
  analyzed_at: string;
}

export class ApiClient {
  private baseUrl: string;
  private apiKey?: string;

  constructor() {
    this.baseUrl = process.env.BACKEND_API_URL || 'http://localhost:8000';
    this.apiKey = process.env.BACKEND_API_KEY;
  }

  async analyze(request: AnalyzeRequest): Promise<AnalysisResult> {
    const url = `${this.baseUrl}/api/v1/analyze`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`API request failed: ${response.status} ${error}`);
    }

    return response.json();
  }

  async getHealth(): Promise<{ status: string; version: string }> {
    const url = `${this.baseUrl}/api/v1/health`;

    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`Health check failed: ${response.status}`);
    }

    return response.json();
  }
}
