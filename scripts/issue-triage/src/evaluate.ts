/**
 * Replays already-triaged issues through the configured provider and scores its
 * answers against the labels humans gave them.
 *
 *   node src/evaluate.ts --limit 300
 *   node src/evaluate.ts --input issues.json   # offline, same shape as Issue[]
 *
 * The provider comes from the environment, see README.md.
 */
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { runEvaluation } from './evaluation.ts';
import { fetchClosedIssues } from './github.ts';
import type { Issue } from './issue.ts';
import { createClassifier, resolveProvider } from './provider.ts';
import { renderEvaluation } from './report.ts';

const { values } = parseArgs({
  options: {
    repo: { type: 'string', default: process.env.GITHUB_REPOSITORY ?? 'OpenCTI-Platform/opencti' },
    limit: { type: 'string', default: '200' },
    input: { type: 'string' },
    out: { type: 'string', default: 'out' },
    concurrency: { type: 'string', default: '8' },
    'keep-title-prefix': { type: 'boolean', default: false },
  },
});

const limit = Number(values.limit);
const concurrency = Number(values.concurrency);
if (!Number.isInteger(limit) || limit < 1 || !Number.isInteger(concurrency) || concurrency < 1) {
  throw new Error('--limit and --concurrency must be positive integers');
}

const provider = resolveProvider();
if (!provider) throw new Error('No provider configured: set TYPESAFE_API_KEY (Jev) or LLM_MODEL (OpenAI-compatible LLM)');

const issues: Issue[] = values.input
  ? (JSON.parse(await readFile(values.input, 'utf8')) as Issue[])
  : await fetchClosedIssues(values.repo, limit, process.env.GITHUB_TOKEN);
console.log(`${issues.length} issues loaded from ${values.input ?? values.repo}`);

const classifier = createClassifier(provider, { keepTitlePrefix: values['keep-title-prefix'] });
const evaluation = await runEvaluation(issues, classifier, concurrency);
const report = renderEvaluation(evaluation, provider);

await mkdir(values.out, { recursive: true });
await writeFile(join(values.out, 'report.md'), report);
await writeFile(join(values.out, 'predictions.json'), JSON.stringify({ provider, ...evaluation }, null, 2));
if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, report);

console.log(report);
console.log(`Written to ${join(values.out, 'report.md')} and ${join(values.out, 'predictions.json')}`);

// A run where every call failed has measured nothing: say so with the exit code.
if (evaluation.evaluated > 0 && evaluation.predictions.length === 0) process.exitCode = 1;
