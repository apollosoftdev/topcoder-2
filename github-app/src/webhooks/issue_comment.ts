import { EmitterWebhookEvent } from '@octokit/webhooks';
import { ApiClient } from '../services/api_client';
import { GitHubService } from '../services/github';

type IssueCommentEvent = EmitterWebhookEvent<'issue_comment.created'>;

const apiClient = new ApiClient();

// Override command pattern: /guardrails override <reason>
const OVERRIDE_PATTERN = /^\/guardrails\s+override\s+(.+)$/i;

export async function handleIssueComment(event: IssueCommentEvent): Promise<void> {
  const { payload } = event;
  const { comment, issue, repository, installation, sender } = payload;

  // Only process comments on pull requests
  if (!issue.pull_request) {
    return;
  }

  if (!installation) {
    console.error('No installation found for webhook event');
    return;
  }

  // Check if comment contains override command
  const commentBody = comment.body?.trim() || '';
  const match = commentBody.match(OVERRIDE_PATTERN);

  if (!match) {
    return; // Not an override command
  }

  const reason = match[1].trim();
  const github = new GitHubService(installation.id);
  const repoFullName = repository.full_name;
  const prNumber = issue.number;
  const username = sender.login;

  console.log(`Processing override request for PR #${prNumber} in ${repoFullName} by ${username}`);

  try {
    // Check if user has write permission on the repository
    const hasPermission = await github.getCollaboratorPermission(
      repository.owner.login,
      repository.name,
      username
    );

    if (!hasPermission) {
      await github.createIssueComment(
        repository.owner.login,
        repository.name,
        prNumber,
        `@${username} You don't have permission to override guardrails checks. ` +
          `Only users with write access or higher can use this command.`
      );
      return;
    }

    // Validate reason length
    if (reason.length < 10) {
      await github.createIssueComment(
        repository.owner.login,
        repository.name,
        prNumber,
        `@${username} Override reason must be at least 10 characters long. ` +
          `Please provide a more detailed reason.`
      );
      return;
    }

    // Get the PR to find the head SHA and check run info
    const pr = await github.getPullRequest(
      repository.owner.login,
      repository.name,
      prNumber
    );

    // Request override from backend
    const overrideResult = await apiClient.requestOverride({
      repository: repoFullName,
      pull_request_number: prNumber,
      request_id: `override-${Date.now()}`, // Generate a request ID for the override
      overridden_by: username,
      reason,
      violations_count: 0, // We don't track this from the comment handler
    });

    if (overrideResult.success) {
      // Find and update the check run to success
      const checkRuns = await github.getCheckRuns(
        repository.owner.login,
        repository.name,
        pr.head.sha
      );

      const guardrailsCheck = checkRuns.find(
        (check) => check.name === 'Enterprise Guardrails'
      );

      if (guardrailsCheck) {
        await github.updateCheckRun(
          repository.owner.login,
          repository.name,
          guardrailsCheck.id,
          'completed',
          'success',
          {
            title: 'Override approved',
            summary: `Check was overridden by @${username}.\n\n**Reason:** ${reason}`,
          }
        );
      }

      // Post confirmation comment
      await github.createIssueComment(
        repository.owner.login,
        repository.name,
        prNumber,
        `✅ **Guardrails Override Approved**\n\n` +
          `Overridden by: @${username}\n` +
          `Reason: ${reason}\n\n` +
          `The blocking check has been updated to allow merge. ` +
          `This override has been logged for audit purposes.`
      );

      console.log(`Override successful for PR #${prNumber} by ${username}`);
    } else {
      await github.createIssueComment(
        repository.owner.login,
        repository.name,
        prNumber,
        `❌ **Override Failed**\n\n` +
          `Failed to process override request: ${overrideResult.message}\n\n` +
          `Please try again or contact your administrator.`
      );
    }
  } catch (error) {
    console.error('Error processing override for PR #%d: %O', prNumber, error);

    try {
      await github.createIssueComment(
        repository.owner.login,
        repository.name,
        prNumber,
        `❌ **Override Error**\n\n` +
          `An error occurred while processing the override request.\n\n` +
          `Error: ${error instanceof Error ? error.message : 'Unknown error'}\n\n` +
          `Please try again or contact your administrator.`
      );
    } catch (commentError) {
      console.error('Failed to post error comment:', commentError);
    }
  }
}
