import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it, expect } from 'vitest';

/**
 * `@filigran/design-system` is a private git dependency, so the frontend
 * install inside the platform image runs behind
 * `RUN --mount=type=secret,id=fds_git_token`. A BuildKit secret that is not
 * provided is not an empty file, it is no file at all: the build dies on
 * `can't open /run/secrets/fds_git_token: No such file or directory`, which
 * reads exactly like an absent repository secret even when the secret exists
 * and is correctly named.
 *
 * Enumerating the install sites by hand missed a caller once already during
 * this migration. This test does the enumeration instead: every
 * `docker/build-push-action` step that builds a Dockerfile requiring the
 * secret, and that does not stop at an earlier `target:`, must declare it.
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
});
