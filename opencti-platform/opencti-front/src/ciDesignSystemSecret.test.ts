import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it, expect } from 'vitest';

/**
 * `@filigran/design-system` is a private git dependency, so the frontend install inside the
 * platform image runs behind `RUN --mount=type=secret,id=fds_git_token`.
 */

const CI_ROOT = path.resolve('../../.github');
const REPO_ROOT = path.resolve('../..');
const SECRET_ID = 'fds_git_token';

const listYamlFiles = async (dir: string): Promise<string[]> => {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = await Promise.all(entries.map(async (entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return listYamlFiles(full);
    return /\.ya?ml$/.test(entry.name) ? [full] : [];
  }));
  return files.flat();
};

/** Splits a YAML job body into its individual `- name:` / `- uses:` steps. */
const splitSteps = (content: string): string[] => content
  .split(/^\s*-\s+(?=(?:name|uses):)/m)
  .slice(1);

const dockerfileNeedsSecret = async (file: string): Promise<boolean> => {
  try {
    const dockerfile = await readFile(path.join(REPO_ROOT, file), 'utf8');
    return dockerfile.includes(`id=${SECRET_ID}`);
  } catch {
    return false;
  }
};

interface BuildStep {
  source: string;
  file: string;
  body: string;
  target?: string;
}

const collectBuildSteps = async (): Promise<BuildStep[]> => {
  const yamlFiles = await listYamlFiles(CI_ROOT);
  const steps: BuildStep[] = [];
  for (const yamlFile of yamlFiles) {
    // eslint-disable-next-line no-await-in-loop
    const content = await readFile(yamlFile, 'utf8');
    for (const body of splitSteps(content)) {
      if (body.includes('docker/build-push-action')) {
        const file = body.match(/^\s*file:\s*(\S+)\s*$/m)?.[1];
        if (file) {
          steps.push({
            source: path.relative(REPO_ROOT, yamlFile),
            file,
            body,
            target: body.match(/^\s*target:\s*(\S+)\s*$/m)?.[1],
          });
        }
      }
    }
  }
  return steps;
};

const buildSteps = await collectBuildSteps();

/** Second enumeration, for the other half of the call graph. */

const SECRET_NAME = 'FDS_GIT_TOKEN';

/** Splits a workflow's `jobs:` mapping into its individual job bodies. */
const splitJobs = (content: string): string[] => content
  .split(/^ {2}(?=[A-Za-z0-9_-]+:\s*$)/m)
  .slice(1);

interface WorkflowFile {
  name: string;
  content: string;
}

const workflows: WorkflowFile[] = await Promise.all(
  (await listYamlFiles(path.join(CI_ROOT, 'workflows'))).map(async (file) => ({
    name: path.basename(file),
    content: await readFile(file, 'utf8'),
  })),
);

/** Reusable workflows that read the secret and must therefore declare it. */
const consumers = workflows.filter(({ content }) => content.includes(`secrets.${SECRET_NAME}`)
  && content.includes('workflow_call:'));

/** Every `uses: ./.github/workflows/<consumer>` job, with the job body around it. */
const callSites = workflows.flatMap(({ name, content }) => splitJobs(content)
  .flatMap((job) => {
    const called = job.match(/^\s*uses:\s*\.\/\.github\/workflows\/(\S+)\s*$/m)?.[1];
    return called && consumers.some((c) => c.name === called)
      ? [{ caller: name, called, job }]
      : [];
  }));

describe('CI wiring for the private design-system dependency', () => {
  it('finds the image build steps to check', () => {
    expect(buildSteps.length).toBeGreaterThan(0);
  });

  it.each(buildSteps)('$source builds $file with the secret it needs', async ({ file, body, target }) => {
    // A step that stops at an earlier stage never reaches the frontend install.
    const reachesInstall = target === undefined || target.startsWith('builder-front');
    const needsSecret = reachesInstall && await dockerfileNeedsSecret(file);
    expect(body.includes(`${SECRET_ID}=`)).toBe(needsSecret);
  });

  it('finds the reusable workflows and call sites to check', () => {
    expect(consumers.length).toBeGreaterThan(0);
    expect(callSites.length).toBeGreaterThan(0);
  });

  it.each(consumers)('$name declares the secret it reads', ({ content }) => {
    const workflowCall = content.slice(content.indexOf('workflow_call:'), content.search(/^jobs:/m));
    expect(workflowCall).toContain(`${SECRET_NAME}:`);
  });

  it.each(callSites)('$caller passes the secret to $called', ({ job }) => {
    expect(/secrets:\s*inherit/.test(job) || job.includes(`${SECRET_NAME}:`)).toBe(true);
  });
});
