import express, { Request, Response } from 'express';
import { Webhooks, createNodeMiddleware } from '@octokit/webhooks';
import dotenv from 'dotenv';

import { handlePullRequest } from './webhooks/pull_request';
import { handlePush } from './webhooks/push';

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Validate required environment variables
const requiredEnvVars = ['GITHUB_APP_ID', 'GITHUB_WEBHOOK_SECRET'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// Initialize webhooks
const webhooks = new Webhooks({
  secret: process.env.GITHUB_WEBHOOK_SECRET!,
});

// Register webhook handlers
webhooks.on('pull_request.opened', handlePullRequest);
webhooks.on('pull_request.synchronize', handlePullRequest);
webhooks.on('pull_request.reopened', handlePullRequest);
webhooks.on('push', handlePush);

// Error handler for webhooks
webhooks.onError((error) => {
  console.error('Webhook error:', error);
});

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// Root endpoint
app.get('/', (_req: Request, res: Response) => {
  res.json({
    name: 'Enterprise Guardrails GitHub App',
    version: '1.0.0',
    status: 'running',
  });
});

// GitHub webhook endpoint
app.use('/webhook', createNodeMiddleware(webhooks, { path: '/' }));

// Start server
app.listen(port, () => {
  console.log(`GitHub App server running on port ${port}`);
  console.log(`Webhook endpoint: http://localhost:${port}/webhook`);
});

export { app, webhooks };
