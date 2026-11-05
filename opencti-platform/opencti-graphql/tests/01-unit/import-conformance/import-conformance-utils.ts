import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { expect } from 'vitest';
import { createImportContext } from '../../../src/intake/stix-import/context';
import { eventBundle, transformBundle } from '../../../src/intake/stix-import/transform';
import { type ImportClient, StixImportError, type StixObject } from '../../../src/intake/stix-import/types';
import { RecordingClient } from './import-conformance-client';

// Fixtures of the STIX import conformance harness, shared with client-python (goldens recorded by
// python -m tests.import_conformance.generate). UPDATE_IMPORT_CONFORMANCE=true rewrites the
// generated inputs instead of checking them.
export const FIXTURES_DIR = join(__dirname, '../../../../../client-python/tests/data/import-conformance/fixtures');
// pycti defects the platform does not reproduce, declared with the port's result (read by both sides)
export const ACCEPTED_DIFFERENCES_FILE = join(__dirname, '../../../../../client-python/tests/data/import-conformance/accepted-differences.json');

export interface GeneratedFixture {
  path: string;
  source: string;
  input: unknown;
  call?: Record<string, unknown>;
}

export const bundleOf = (...objects: unknown[]) => ({ type: 'bundle', id: 'bundle--00000000-0000-4000-8000-000000000000', objects });

const serialize = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

export const writeOrCheckFixture = (fixture: GeneratedFixture) => {
  const dir = join(FIXTURES_DIR, fixture.path);
  const files: Record<string, string> = { 'input.json': serialize(fixture.input), SOURCE: `${fixture.source}\n` };
  if (fixture.call) {
    files['call.json'] = serialize(fixture.call);
  }
  if (process.env.UPDATE_IMPORT_CONFORMANCE === 'true') {
    mkdirSync(dir, { recursive: true });
    Object.entries(files).forEach(([name, content]) => writeFileSync(join(dir, name), content));
    if (!fixture.call) {
      rmSync(join(dir, 'call.json'), { force: true });
    }
  }
  if (!fixture.call) {
    expect(existsSync(join(dir, 'call.json')), `stale ${fixture.path}/call.json`).toBe(false);
  }
  Object.entries(files).forEach(([name, content]) => {
    expect(existsSync(join(dir, name)), `missing ${fixture.path}/${name}`).toBe(true);
    expect(readFileSync(join(dir, name), 'utf-8'), `${fixture.path}/${name}`).toEqual(content);
  });
};

// A generator marks its fixtures with a SOURCE prefix: a fixture carrying it that the generator
// does not produce anymore is stale (its case was removed or renamed) and must be deleted
export const expectNoOrphanFixtures = (sourcePrefix: string, generated: GeneratedFixture[]) => {
  const paths = new Set(generated.map((fixture) => fixture.path));
  const orphans = (readdirSync(FIXTURES_DIR, { recursive: true }) as string[])
    .filter((path) => path.endsWith(`${sep}SOURCE`))
    .map((path) => dirname(path))
    .filter((dir) => readFileSync(join(FIXTURES_DIR, dir, 'SOURCE'), 'utf-8').startsWith(sourcePrefix))
    .map((dir) => dir.split(sep).join('/'))
    .filter((dir) => !paths.has(dir))
    .sort();
  expect(orphans, `fixtures marked ${sourcePrefix} that are not generated anymore: delete them`).toEqual([]);
};

// The call of a fixture (call.json) when it declares nothing, as the recorder's DEFAULT_CALL
export const DEFAULT_CALL = { update: false, types: null, now: '2026-01-01T00:00:00+00:00', expect_errors: false, message_type: 'bundle' };
export type FixtureCall = typeof DEFAULT_CALL & { types: string[] | null };

// The port's transformation of one message, recorded as the recorder records pycti's (calls,
// items, incompatible, bundle_error, logged_errors). A bundle error is a StixImportError only
// (pycti's error ending the whole message): any other error is a defect of the port and is thrown.
// track: false keeps the calls out of SEEN_DOCUMENTS and SEEN_CALLS (runs on inputs without golden);
// beforeQuery runs before each call (a call budget).
export const transformMessage = async (dir: string, call: FixtureCall, input: StixObject, track = true, beforeQuery?: () => void) => {
  const client = new RecordingClient(dir, track);
  const withBudget: ImportClient = {
    query: (document, variables) => {
      beforeQuery?.();
      return client.query(document, variables);
    },
  };
  const importClient = beforeQuery ? withBudget : client;
  const loggedErrors: string[] = [];
  const context = createImportContext(importClient, { error: (message) => loggedErrors.push(message), warn: () => {} }, { now: new Date(call.now) });
  let result: { items: { id: string; outcome: string }[]; incompatible: unknown[] } = { items: [], incompatible: [] };
  let bundleError: string | null = null;
  try {
    if (call.message_type === 'event') {
      // pycti's splitter gives a bundle without id the nil uuid in the recorder (uuid4 patched)
      const bundle = { id: 'bundle--00000000-0000-0000-0000-000000000000', ...eventBundle(input) };
      result = await transformBundle(context, bundle, true, call.types);
    } else {
      result = await transformBundle(context, input, call.update, call.types);
    }
  } catch (error) {
    if (!(error instanceof StixImportError)) {
      throw error;
    }
    bundleError = error.name;
  }
  return { calls: client.calls, ...result, bundle_error: bundleError, logged_errors: loggedErrors };
};
