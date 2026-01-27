import { Octokit } from '@octokit/rest';
import { createAppAuth } from '@octokit/auth-app';

interface CheckOutput {
  title: string;
  summary: string;
  text?: string;
  annotations?: Array<{
    path: string;
    start_line: number;
    end_line: number;
    annotation_level: 'notice' | 'warning' | 'failure';
    message: string;
    title?: string;
  }>;
}

export class GitHubService {
  private octokit: Octokit;

  constructor(installationId: number) {
    const appId = process.env.GITHUB_APP_ID!;
    const privateKey = process.env.GITHUB_PRIVATE_KEY!;

    this.octokit = new Octokit({
      authStrategy: createAppAuth,
      auth: {
        appId,
        privateKey,
        installationId,
      },
    });
  }

  async getPullRequestDiff(
    owner: string,
    repo: string,
    pullNumber: number
  ): Promise<string> {
    const response = await this.octokit.pulls.get({
      owner,
      repo,
      pull_number: pullNumber,
      mediaType: {
        format: 'diff',
      },
    });

    return response.data as unknown as string;
  }

  async getPullRequestFiles(
    owner: string,
    repo: string,
    pullNumber: number
  ): Promise<Array<{ filename: string; status: string; additions: number; deletions: number }>> {
    const response = await this.octokit.pulls.listFiles({
      owner,
      repo,
      pull_number: pullNumber,
    });

    return response.data.map((file) => ({
      filename: file.filename,
      status: file.status,
      additions: file.additions,
      deletions: file.deletions,
    }));
  }

  async getCommitDiff(
    owner: string,
    repo: string,
    baseSha: string,
    headSha: string
  ): Promise<string> {
    const response = await this.octokit.repos.compareCommits({
      owner,
      repo,
      base: baseSha,
      head: headSha,
      mediaType: {
        format: 'diff',
      },
    });

    return response.data as unknown as string;
  }

  async createCheckRun(
    owner: string,
    repo: string,
    headSha: string,
    name: string,
    status: 'queued' | 'in_progress' | 'completed',
    output: CheckOutput,
    conclusion?: 'success' | 'failure' | 'neutral' | 'cancelled' | 'skipped' | 'timed_out'
  ): Promise<number> {
    const response = await this.octokit.checks.create({
      owner,
      repo,
      name,
      head_sha: headSha,
      status,
      conclusion: status === 'completed' ? conclusion : undefined,
      output,
    });

    return response.data.id;
  }

  async updateCheckRun(
    owner: string,
    repo: string,
    checkRunId: number,
    status: 'queued' | 'in_progress' | 'completed',
    conclusion: 'success' | 'failure' | 'neutral' | 'cancelled' | 'skipped' | 'timed_out',
    output: CheckOutput
  ): Promise<void> {
    await this.octokit.checks.update({
      owner,
      repo,
      check_run_id: checkRunId,
      status,
      conclusion,
      output,
    });
  }

  async createPullRequestComment(
    owner: string,
    repo: string,
    pullNumber: number,
    body: string,
    commitSha: string,
    path: string,
    line: number
  ): Promise<void> {
    try {
      await this.octokit.pulls.createReviewComment({
        owner,
        repo,
        pull_number: pullNumber,
        body,
        commit_id: commitSha,
        path,
        line,
        side: 'RIGHT',
      });
    } catch (error) {
      // If line comment fails, try creating a general review comment
      console.warn(`Failed to create line comment at ${path}:${line}, creating general comment`);
      await this.octokit.pulls.createReview({
        owner,
        repo,
        pull_number: pullNumber,
        body: `**${path}:${line}**\n\n${body}`,
        event: 'COMMENT',
      });
    }
  }

  async createIssueComment(
    owner: string,
    repo: string,
    issueNumber: number,
    body: string
  ): Promise<number> {
    const response = await this.octokit.issues.createComment({
      owner,
      repo,
      issue_number: issueNumber,
      body,
    });

    return response.data.id;
  }

  async getIssueComments(
    owner: string,
    repo: string,
    issueNumber: number
  ): Promise<Array<{ id: number; body?: string }>> {
    const response = await this.octokit.issues.listComments({
      owner,
      repo,
      issue_number: issueNumber,
    });

    return response.data.map((comment) => ({
      id: comment.id,
      body: comment.body,
    }));
  }

  async updateIssueComment(
    owner: string,
    repo: string,
    commentId: number,
    body: string
  ): Promise<void> {
    await this.octokit.issues.updateComment({
      owner,
      repo,
      comment_id: commentId,
      body,
    });
  }

  async createIssue(
    owner: string,
    repo: string,
    title: string,
    body: string,
    labels?: string[]
  ): Promise<number> {
    const response = await this.octokit.issues.create({
      owner,
      repo,
      title,
      body,
      labels,
    });

    return response.data.number;
  }

  async getCollaboratorPermission(
    owner: string,
    repo: string,
    username: string
  ): Promise<boolean> {
    try {
      const response = await this.octokit.repos.getCollaboratorPermissionLevel({
        owner,
        repo,
        username,
      });

      // Users with write, maintain, or admin permission can override
      const allowedPermissions = ['write', 'maintain', 'admin'];
      return allowedPermissions.includes(response.data.permission);
    } catch (error) {
      console.error(`Failed to get permission for ${username}:`, error);
      return false;
    }
  }

  async getPullRequest(
    owner: string,
    repo: string,
    pullNumber: number
  ): Promise<{
    head: { sha: string };
    base: { sha: string };
    number: number;
    state: string;
  }> {
    const response = await this.octokit.pulls.get({
      owner,
      repo,
      pull_number: pullNumber,
    });

    return {
      head: { sha: response.data.head.sha },
      base: { sha: response.data.base.sha },
      number: response.data.number,
      state: response.data.state,
    };
  }

  async getCheckRuns(
    owner: string,
    repo: string,
    ref: string
  ): Promise<Array<{ id: number; name: string; status: string; conclusion: string | null }>> {
    const response = await this.octokit.checks.listForRef({
      owner,
      repo,
      ref,
    });

    return response.data.check_runs.map((check) => ({
      id: check.id,
      name: check.name,
      status: check.status,
      conclusion: check.conclusion,
    }));
  }
}
