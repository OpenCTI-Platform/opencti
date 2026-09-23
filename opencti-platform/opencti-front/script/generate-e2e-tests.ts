import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

// Authoring-time step of the agentic e2e POC (Topic 6).
//
// Reads tests_e2e/agentic/scenario.txt, skips any [scenario] block already
// marked `implemented: true`, and asks the local Copilot CLI instance —
// which has full repo context — to generate one Playwright spec per
// remaining block into tests_e2e/agentic/generated/.
//
// This script never runs in CI. It is invoked by a human, before pushing,
// via `yarn e2e:generate`. The generated specs are committed and reviewed
// like any other test; CI only ever executes them (see
// .github/workflows/agentic-e2e-poc.yml), it never calls Copilot.

interface Scenario {
  name: string;
  implemented: boolean;
  raw: string; // the exact source block, used to patch the file back
}

const scenarioFile = path.join('tests_e2e', 'agentic', 'scenario.txt');
const outputDir = path.join('tests_e2e', 'agentic', 'generated');

const parseScenarios = (content: string): Scenario[] => {
  const blocks = content.split(/(?=^\[scenario:)/m).filter((b) => b.trim().startsWith('[scenario:'));
  return blocks.map((block) => {
    const nameMatch = block.match(/^\[scenario:\s*([^\]]+)]/);
    const implementedMatch = block.match(/^implemented:\s*(true|false)\s*$/m);
    return {
      name: nameMatch ? nameMatch[1].trim() : 'unknown',
      implemented: implementedMatch ? implementedMatch[1] === 'true' : false,
      raw: block,
    };
  });
};

const log = (message: string) => {
  console.log(`[e2e:generate] ${message}`);
};

const main = async () => {
  log(`reading ${scenarioFile}`);
  const content = await readFile(scenarioFile, 'utf-8');
  const scenarios = parseScenarios(content);

  log(`found ${scenarios.length} scenario(s): ${scenarios.map((s) => s.name).join(', ') || 'none'}`);

  const pending = scenarios.filter((s) => !s.implemented);
  if (pending.length === 0) {
    log('nothing to do, every scenario is already marked implemented: true');
    return;
  }

  log(`${pending.length} scenario(s) need generation: ${pending.map((s) => s.name).join(', ')}`);
  const skipped = scenarios.length - pending.length;
  if (skipped > 0) {
    log(`skipping ${skipped} already-implemented scenario(s)`);
  }

  const prompt = `Read ${scenarioFile}. Generate a Playwright test for only these
scenarios, by name: ${pending.map((s) => s.name).join(', ')}. Ignore every other
[scenario] block in the file. For each one, write
${outputDir}/<name>.spec.ts. Tag every generated test with '@agentic' (in
addition to any other tag such as '@ce') so the whole batch can be run with
\`yarn test:e2e --grep @agentic\` — never rely on a path filter, it skips the
'setup'/'init data' dependency projects and breaks authentication. Reuse
existing page objects and fixtures from tests_e2e/model and
tests_e2e/fixtures where they already cover the needed navigation or
selectors; only add new locators when nothing reusable exists. The "success"
line in each block is the exact assertion to write — do not add extra
assertions beyond it. Do not modify any file outside ${outputDir}.`;

  log('invoking copilot (this can take a while, output below is Copilot\'s own progress)...');
  const startedAt = Date.now();
  try {
    execFileSync('copilot', [
      '-p', prompt,
      '--no-ask-user',
      '--allow-tool', 'read',
      '--allow-tool', 'write',
    ], { stdio: 'inherit' });
  } catch (error) {
    log(`copilot invocation failed: ${(error as Error).message}`);
    process.exitCode = 1;
    return;
  }
  log(`copilot finished in ${((Date.now() - startedAt) / 1000).toFixed(1)}s`);

  let updatedContent = content;
  let markedCount = 0;
  for (const scenario of pending) {
    const generatedPath = path.join(outputDir, `${scenario.name}.spec.ts`);
    if (!existsSync(generatedPath)) {
      log(`WARNING: ${generatedPath} was not created, leaving implemented: false for "${scenario.name}"`);
      continue;
    }
    const patchedBlock = /^implemented:\s*(true|false)\s*$/m.test(scenario.raw)
      ? scenario.raw.replace(/^implemented:\s*(true|false)\s*$/m, 'implemented: true')
      : `${scenario.raw.trimEnd()}\nimplemented: true\n`;
    updatedContent = updatedContent.replace(scenario.raw, patchedBlock);
    markedCount += 1;
    log(`generated ${generatedPath}, marking "${scenario.name}" as implemented: true`);
  }

  if (markedCount > 0) {
    await writeFile(scenarioFile, updatedContent);
    log(`updated ${scenarioFile} (${markedCount} scenario(s) marked implemented)`);
  }

  log('done. Review the generated file(s) before committing.');
};

await main();
