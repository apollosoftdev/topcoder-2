import express, { Request, Response } from "express";
import { Webhooks, createNodeMiddleware } from "@octokit/webhooks";
import dotenv from "dotenv";
import path from "path";

import { handlePullRequest } from "./webhooks/pull_request";
import { handlePush } from "./webhooks/push";
import { handleIssueComment } from "./webhooks/issue_comment";

// Load environment variables from github-app/.env file
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const app = express();
const port = process.env.PORT || 3000;

// Validate required environment variables using explicit checks
// to avoid object injection vulnerabilities from bracket notation
const missingEnvVars: string[] = [];

if (!process.env.GITHUB_APP_ID) {
  missingEnvVars.push("GITHUB_APP_ID");
}
if (!process.env.GITHUB_WEBHOOK_SECRET) {
  missingEnvVars.push("GITHUB_WEBHOOK_SECRET");
}
if (!process.env.GITHUB_PRIVATE_KEY) {
  missingEnvVars.push("GITHUB_PRIVATE_KEY");
}
if (!process.env.BACKEND_API_URL) {
  missingEnvVars.push("BACKEND_API_URL");
}

if (missingEnvVars.length > 0) {
  console.error("Missing required environment variables:");
  for (const envVar of missingEnvVars) {
    console.error("  - %s", envVar);
  }
  console.error("\nPlease set these variables in your .env file or environment.");
  process.exit(1);
}

// Initialize webhooks
const webhooks = new Webhooks({
  secret: process.env.GITHUB_WEBHOOK_SECRET!,
});

// Register webhook handlers
webhooks.on("pull_request.opened", handlePullRequest);
webhooks.on("pull_request.synchronize", handlePullRequest);
webhooks.on("pull_request.reopened", handlePullRequest);
webhooks.on("push", handlePush);
webhooks.on("issue_comment.created", handleIssueComment);

// Error handler for webhooks
webhooks.onError((error) => {
  console.error("Webhook error:", error);
});

// Health check endpoint
app.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "healthy",
    version: "1.0.0",
    timestamp: new Date().toISOString(),
  });
});

// Root endpoint
app.get("/", (_req: Request, res: Response) => {
  res.json({
    name: "Enterprise Guardrails GitHub App",
    version: "1.0.0",
    status: "running",
  });
});

// GitHub webhook endpoint
app.use("/webhook", createNodeMiddleware(webhooks, { path: "/" }));

// Start server
app.listen(port, () => {
  console.log(`GitHub App server running on port ${port}`);
  console.log(`Webhook endpoint: http://localhost:${port}/webhook`);
});

export { app, webhooks };
