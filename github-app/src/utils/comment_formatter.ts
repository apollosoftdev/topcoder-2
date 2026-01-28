import { AnalysisResult, Violation } from '../services/api_client';

interface CheckAnnotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: 'notice' | 'warning' | 'failure';
  message: string;
  title?: string;
}

/**
 * Escapes HTML entities to prevent XSS in generated content.
 */
function escapeHtml(text: string): string {
  // Use explicit switch to avoid object bracket notation
  return text.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      case "'":
        return '&#39;';
      default:
        return char;
    }
  });
}

export class CommentFormatter {
  formatInlineComment(violation: Violation): string {
    const severityEmoji = this.getSeverityEmoji(violation.severity);
    const severityBadge = this.getSeverityBadge(violation.severity);

    let comment = `${severityEmoji} **${severityBadge}** ${violation.message}\n\n`;

    if (violation.suggestion) {
      comment += `**Suggestion:** ${violation.suggestion}\n\n`;
    }

    if (violation.cwe || violation.owasp) {
      comment += '**References:** ';
      const refs = [];
      if (violation.cwe) refs.push(`[${violation.cwe}](https://cwe.mitre.org/data/definitions/${violation.cwe.replace('CWE-', '')}.html)`);
      if (violation.owasp) refs.push(violation.owasp);
      comment += refs.join(' | ') + '\n';
    }

    comment += `\n<sub>Rule: \`${escapeHtml(violation.rule)}\`</sub>`;

    return comment;
  }

  formatSummaryComment(result: AnalysisResult): string {
    let comment = '<!-- enterprise-guardrails-summary -->\n';
    comment += '## Enterprise Guardrails Analysis\n\n';

    // Summary section
    comment += `**Status:** ${result.should_block ? '❌ Blocking' : '✅ Passed'}\n`;
    comment += `**Enforcement Mode:** ${result.enforcement_action}\n`;
    comment += `**Analyzed at:** ${new Date(result.analyzed_at).toUTCString()}\n\n`;

    // Violations summary
    const criticalCount = result.violations.filter((v) => v.severity === 'critical').length;
    const highCount = result.violations.filter((v) => v.severity === 'high').length;
    const mediumCount = result.violations.filter((v) => v.severity === 'medium').length;
    const lowCount = result.violations.filter((v) => v.severity === 'low').length;

    comment += '### Violations Summary\n\n';
    comment += '| Severity | Count |\n';
    comment += '|----------|-------|\n';
    comment += `| 🔴 Critical | ${criticalCount} |\n`;
    comment += `| 🟠 High | ${highCount} |\n`;
    comment += `| 🟡 Medium | ${mediumCount} |\n`;
    comment += `| 🔵 Low | ${lowCount} |\n\n`;

    // Violations details
    if (result.violations.length > 0) {
      comment += '### Violations Detail\n\n';

      for (const violation of result.violations.slice(0, 20)) {
        const emoji = this.getSeverityEmoji(violation.severity);
        comment += `<details>\n`;
        // nosemgrep: javascript.lang.security.html-in-template-string.html-in-template-string
        comment += `<summary>${emoji} <b>${escapeHtml(violation.file)}:${violation.line}</b> - ${escapeHtml(violation.message)}</summary>\n\n`;
        comment += `- **Rule:** \`${escapeHtml(violation.rule)}\`\n`;
        comment += `- **Severity:** ${escapeHtml(violation.severity)}\n`;
        if (violation.suggestion) {
          comment += `- **Suggestion:** ${escapeHtml(violation.suggestion)}\n`;
        }
        if (violation.cwe) {
          comment += `- **CWE:** [${violation.cwe}](https://cwe.mitre.org/data/definitions/${violation.cwe.replace('CWE-', '')}.html)\n`;
        }
        if (violation.owasp) {
          comment += `- **OWASP:** ${violation.owasp}\n`;
        }
        if (violation.code_snippet) {
          comment += `\n\`\`\`\n${violation.code_snippet}\n\`\`\`\n`;
        }
        comment += '</details>\n\n';
      }

      if (result.violations.length > 20) {
        comment += `*... and ${result.violations.length - 20} more violations*\n\n`;
      }
    }

    // AI Review section
    if (result.ai_review) {
      comment += '### AI Review\n\n';
      comment += `**Risk Score:** ${this.getRiskScoreIndicator(result.ai_review.risk_score)}\n\n`;
      comment += `${result.ai_review.summary}\n\n`;

      if (result.ai_review.recommendations.length > 0) {
        comment += '**Recommendations:**\n';
        for (const rec of result.ai_review.recommendations) {
          comment += `- ${rec}\n`;
        }
        comment += '\n';
      }
    }

    // Copilot detection section
    if (result.copilot_detection?.detected) {
      comment += '### AI-Generated Code Detection\n\n';
      comment += `**Confidence:** ${result.copilot_detection.confidence}%\n\n`;
      comment += '**Indicators:**\n';
      for (const indicator of result.copilot_detection.indicators) {
        comment += `- ${indicator}\n`;
      }
      comment += '\n';
    }

    comment += '---\n';
    comment += '*Powered by Enterprise Guardrails*';

    return comment;
  }

  formatCheckSummary(result: AnalysisResult): string {
    let summary = `## Analysis Results\n\n`;
    summary += `${result.summary}\n\n`;

    const criticalCount = result.violations.filter((v) => v.severity === 'critical').length;
    const highCount = result.violations.filter((v) => v.severity === 'high').length;
    const mediumCount = result.violations.filter((v) => v.severity === 'medium').length;
    const lowCount = result.violations.filter((v) => v.severity === 'low').length;

    summary += '### Violations by Severity\n\n';
    summary += `- Critical: ${criticalCount}\n`;
    summary += `- High: ${highCount}\n`;
    summary += `- Medium: ${mediumCount}\n`;
    summary += `- Low: ${lowCount}\n\n`;

    if (result.ai_review) {
      summary += `### AI Analysis\n\n`;
      summary += `Risk Score: ${result.ai_review.risk_score}/100\n\n`;
      summary += `${result.ai_review.summary}\n`;
    }

    return summary;
  }

  formatAnnotations(result: AnalysisResult): CheckAnnotation[] {
    const annotations: CheckAnnotation[] = [];

    for (const violation of result.violations.slice(0, 50)) {
      // GitHub limits to 50 annotations
      const level = this.severityToAnnotationLevel(violation.severity);

      annotations.push({
        path: violation.file,
        start_line: violation.line,
        end_line: violation.line,
        annotation_level: level,
        title: `[${violation.severity.toUpperCase()}] ${violation.rule}`,
        message: `${violation.message}\n\nSuggestion: ${violation.suggestion || 'N/A'}`,
      });
    }

    return annotations;
  }

  private getSeverityEmoji(severity: string): string {
    switch (severity.toLowerCase()) {
      case 'critical':
        return '🔴';
      case 'high':
        return '🟠';
      case 'medium':
        return '🟡';
      case 'low':
        return '🔵';
      default:
        return '⚪';
    }
  }

  private getSeverityBadge(severity: string): string {
    return severity.toUpperCase();
  }

  private severityToAnnotationLevel(severity: string): 'notice' | 'warning' | 'failure' {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'failure';
      case 'medium':
        return 'warning';
      default:
        return 'notice';
    }
  }

  private getRiskScoreIndicator(score: number): string {
    if (score >= 80) return `🔴 ${score}/100 (Critical)`;
    if (score >= 60) return `🟠 ${score}/100 (High)`;
    if (score >= 40) return `🟡 ${score}/100 (Medium)`;
    if (score >= 20) return `🔵 ${score}/100 (Low)`;
    return `🟢 ${score}/100 (Minimal)`;
  }
}
