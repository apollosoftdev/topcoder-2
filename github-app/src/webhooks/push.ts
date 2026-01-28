import { EmitterWebhookEvent } from '@octokit/webhooks';
import { ApiClient } from '../services/api_client';
import { GitHubService } from '../services/github';

type PushEvent = EmitterWebhookEvent<'push'>;

const apiClient = new ApiClient();

export async function handlePush(event: PushEvent): Promise<void> {
  const { payload } = event;
  const { repository, commits, ref, installation, after, before } = payload;

  // Only process pushes to main/master branches for audit logging
  const branch = ref.replace('refs/heads/', '');
  const isMainBranch = ['main', 'master'].includes(branch);

  if (!installation) {
    console.error('No installation found for push event');
    return;
  }

  if (!commits || commits.length === 0) {
    console.log('No commits to process');
    return;
  }

  const github = new GitHubService(installation.id);
  const repoFullName = repository.full_name;

  console.log(`Processing push to ${branch} in ${repoFullName} (${commits.length} commits)`);

  try {
    // Get the diff for the push
    const diff = await github.getCommitDiff(
      repository.owner.name || repository.owner.login,
      repository.name,
      before,
      after
    );

    // Get changed files
    const changedFiles = new Set<string>();
    for (const commit of commits) {
      (commit.added || []).forEach((f: string) => changedFiles.add(f));
      (commit.modified || []).forEach((f: string) => changedFiles.add(f));
    }

    // Determine rule packs
    const rulePacks = ['security'];

    // Run analysis for audit purposes
    const result = await apiClient.analyze({
      repository: repoFullName,
      commit_sha: after,
      diff,
      files: Array.from(changedFiles),
      config: {
        enforcement_mode: isMainBranch ? 'warning' : 'advisory',
        rule_packs: rulePacks,
        ai_review_enabled: isMainBranch, // Only AI review for main branch
        copilot_detection_enabled: true,
      },
    });

    console.log(
      `Push analysis complete: ${result.violations.length} violations found`
    );

    // For main branch pushes with critical violations, create an issue
    if (isMainBranch && result.violations.some((v) => v.severity === 'critical')) {
      await createSecurityIssue(github, repository, after, result);
    }
  } catch (error) {
    console.error('Error processing push to %s: %O', branch, error);
  }
}

async function createSecurityIssue(
  github: GitHubService,
  repository: PushEvent['payload']['repository'],
  commitSha: string,
  result: { violations: Array<{ severity: string; message: string; file: string; line: number }> }
): Promise<void> {
  const criticalViolations = result.violations.filter(
    (v) => v.severity === 'critical'
  );

  const title = `Security Alert: ${criticalViolations.length} critical violation(s) in ${commitSha.substring(0, 7)}`;

  let body = `## Critical Security Violations Detected\n\n`;
  body += `**Commit:** ${commitSha}\n\n`;
  body += `### Violations\n\n`;

  for (const violation of criticalViolations) {
    body += `- **${violation.file}:${violation.line}** - ${violation.message}\n`;
  }

  body += `\n---\n`;
  body += `*This issue was automatically created by Enterprise Guardrails.*`;

  try {
    await github.createIssue(
      repository.owner.name || repository.owner.login,
      repository.name,
      title,
      body,
      ['security', 'automated']
    );

    console.log(`Created security issue for commit ${commitSha}`);
  } catch (error) {
    console.error('Failed to create security issue:', error);
  }
}
