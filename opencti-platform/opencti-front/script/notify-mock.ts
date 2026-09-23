// Output step of the agentic e2e POC (Topic 6). Runs only in CI, after
// Playwright has executed the generated specs. Reads the JSON reporter
// output and prints the payload that would be pushed to Teams/Slack/Notion.
//
// MVP scope: no real webhook call yet. This validates the payload shape
// before wiring a destination.
import { readFile } from 'node:fs/promises';

const reportPath = process.argv[2] ?? 'test-results/results.json';
const status = process.argv[3]?.replace('--status=', '') ?? 'unknown';

const summarize = async () => {
  let scenariosRun: unknown = 'unavailable';
  try {
    const raw = await readFile(reportPath, 'utf-8');
    const report = JSON.parse(raw);
    scenariosRun = report.suites?.flatMap((s: { specs?: unknown[] }) => s.specs ?? []).length ?? 'unknown';
  } catch {
    // report not found or not JSON — keep the mock output useful anyway
  }

  const payload = {
    channel: 'teams|slack|notion (mocked, no webhook wired yet)',
    status,
    scenarios_run: scenariosRun,
    timestamp: new Date().toISOString(),
  };

  console.log(JSON.stringify(payload, null, 2));
};

await summarize();
