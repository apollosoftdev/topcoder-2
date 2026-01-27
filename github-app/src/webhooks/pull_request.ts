import { EmitterWebhookEvent } from '@octokit/webhooks';
import { ApiClient, AnalysisResult } from '../services/api_client';
import { GitHubService } from '../services/github';
import { CommentFormatter } from '../utils/comment_formatter';

type PullRequestEvent = EmitterWebhookEvent<
  'pull_request.opened' | 'pull_request.synchronize' | 'pull_request.reopened'
>;

const apiClient = new ApiClient();
const formatter = new CommentFormatter();

export async function handlePullRequest(event: PullRequestEvent): Promise<void> {
  const { payload } = event;
  const { pull_request: pr, repository, installation } = payload;

  if (!installation) {
    console.error('No installation found for webhook event');
    return;
  }

  const github = new GitHubService(installation.id);
  const repoFullName = repository.full_name;
  const prNumber = pr.number;

  console.log(`Processing PR #${prNumber} in ${repoFullName}`);

  try {
    // Create a check run to show analysis is in progress
    const checkRunId = await github.createCheckRun(
      repository.owner.login,
      repository.name,
      pr.head.sha,
      'Enterprise Guardrails',
      'in_progress',
      {
        title: 'Analyzing code changes...',
        summary: 'Security and compliance analysis is in progress.',
      }
    );

    // Get the PR diff
    const diff = await github.getPullRequestDiff(
      repository.owner.login,
      repository.name,
      prNumber
    );

    // Get the list of changed files
    const files = await github.getPullRequestFiles(
      repository.owner.login,
      repository.name,
      prNumber
    );

    // Determine rule packs based on repository configuration
    // In a real implementation, this could read from .github/guardrails.yml
    const rulePacks = ['security'];

    // Call the backend API for analysis
    const result = await apiClient.analyze({
      repository: repoFullName,
      pull_request_number: prNumber,
      commit_sha: pr.head.sha,
      diff,
      files: files.map((f) => f.filename),
      config: {
        enforcement_mode: 'warning',
        rule_packs: rulePacks,
        ai_review_enabled: true,
        copilot_detection_enabled: true,
      },
    });

    console.log(
      `Analysis complete: ${result.violations.length} violations, ` +
        `should_block=${result.should_block}`
    );

    // Post PR comments for violations
    await postViolationComments(github, repository, pr, result);

    // Post summary comment
    await postSummaryComment(github, repository, prNumber, result);

    // Update check run with results
    const checkConclusion = result.should_block ? 'failure' : 'success';
    const checkTitle = result.should_block
      ? `Found ${result.violations.length} blocking violation(s)`
      : result.violations.length > 0
        ? `Found ${result.violations.length} issue(s)`
        : 'No issues found';

    await github.updateCheckRun(
      repository.owner.login,
      repository.name,
      checkRunId,
      'completed',
      checkConclusion,
      {
        title: checkTitle,
        summary: formatter.formatCheckSummary(result),
        annotations: formatter.formatAnnotations(result),
      }
    );

    console.log(`PR #${prNumber} analysis complete: ${checkConclusion}`);
  } catch (error) {
    console.error(`Error processing PR #${prNumber}:`, error);

    // Try to update check run to indicate failure
    try {
      await github.createCheckRun(
        repository.owner.login,
        repository.name,
        pr.head.sha,
        'Enterprise Guardrails',
        'completed',
        {
          title: 'Analysis failed',
          summary: `An error occurred during analysis: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
        'failure'
      );
    } catch (checkError) {
      console.error('Failed to update check run:', checkError);
    }
  }
}

async function postViolationComments(
  github: GitHubService,
  repository: PullRequestEvent['payload']['repository'],
  pr: PullRequestEvent['payload']['pull_request'],
  result: AnalysisResult
): Promise<void> {
  // Post inline comments for each violation
  for (const violation of result.violations.slice(0, 10)) {
    // Limit to 10 inline comments
    try {
      const body = formatter.formatInlineComment(violation);

      await github.createPullRequestComment(
        repository.owner.login,
        repository.name,
        pr.number,
        body,
        pr.head.sha,
        violation.file,
        violation.line
      );
    } catch (error) {
      console.error(`Failed to post comment for ${violation.file}:${violation.line}:`, error);
    }
  }
}

async function postSummaryComment(
  github: GitHubService,
  repository: PullRequestEvent['payload']['repository'],
  prNumber: number,
  result: AnalysisResult
): Promise<void> {
  const body = formatter.formatSummaryComment(result);

  // Look for existing summary comment to update
  const comments = await github.getIssueComments(
    repository.owner.login,
    repository.name,
    prNumber
  );

  const existingComment = comments.find(
    (c) => c.body?.includes('<!-- enterprise-guardrails-summary -->')
  );

  if (existingComment) {
    await github.updateIssueComment(
      repository.owner.login,
      repository.name,
      existingComment.id,
      body
    );
  } else {
    await github.createIssueComment(
      repository.owner.login,
      repository.name,
      prNumber,
      body
    );
  }
}
