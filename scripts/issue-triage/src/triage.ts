/**
 * Shadow triage of one issue: asks the configured provider, writes the suggestion to the job
 * summary and, only when TRIAGE_POST_COMMENT=true, as a comment on the issue.
 * It never applies a label.
 */
import { appendFile } from 'node:fs/promises';
import { fetchIssue, postComment } from './github.ts';
import { createClassifier, resolveProvider } from './provider.ts';
import { renderTriage } from './report.ts';

const repo = process.env.GITHUB_REPOSITORY;
const issueNumber = Number(process.env.ISSUE_NUMBER);
const token = process.env.GITHUB_TOKEN;
if (!repo || !Number.isInteger(issueNumber) || issueNumber < 1) {
  throw new Error('GITHUB_REPOSITORY and ISSUE_NUMBER are required');
}

const provider = resolveProvider();
if (!provider) {
  // Lets the workflow sit in the repository before any secret exists.
  console.log('::notice::No triage provider configured (TYPESAFE_API_KEY or LLM_MODEL), issue triage skipped');
} else {
  const issue = await fetchIssue(repo, issueNumber, token);
  const decision = await createClassifier(provider).classify(issue);
  const summary = renderTriage(issueNumber, decision);

  console.log(summary);
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, summary);
  if (process.env.TRIAGE_POST_COMMENT === 'true') {
    if (!token) throw new Error('GITHUB_TOKEN is required to post the comment');
    await postComment(repo, issueNumber, summary, token);
  }
}
