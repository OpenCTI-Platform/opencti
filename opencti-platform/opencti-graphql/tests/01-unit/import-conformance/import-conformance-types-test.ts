import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, sep } from 'node:path';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../src/types/stix-2-1-extensions';
import { ImportClientError, StixImportError, type StixObject } from '../../../src/intake/stix-import/types';
import { DEFAULT_CALL, FIXTURES_DIR, type FixtureCall, transformMessage } from './import-conformance-utils';

// Wrongly typed fields: each field of the fixtures' objects (top level and OpenCTI extensions, but
// id and type), replaced by a value of each JSON type, must give an outcome pycti can give: the
// object transformed, or the Python error pycti raises (a StixImportError, or a GraphQL error as
// pycti's ValueError). A native JavaScript error (reading a property of a number, `in` on a
// string...) is a defect of the port: transformBundle throws it instead of an outcome. The goldens
// check which outcome; this test checks that every input gives one, on inputs without golden.

const VALUES: unknown[] = [5, 1.5, true, '', 'x', [], ['x'], {}, { k: 'v' }, null];
const OPENCTI_EXTENSIONS = [STIX_EXT_OCTI, STIX_EXT_OCTI_SCO];
// Python error names an object outcome can carry (StixImportError names, ValueError for a GraphQL error)
const PYTHON_OUTCOMES = new Set(['ValueError', 'TypeError', 'KeyError', 'IndexError', 'AttributeError', 'Error']);
// A message the port transforms with more calls is looping (rule apply or rescan never complete)
const CALL_BUDGET = 500;

const isDict = (value: unknown): value is StixObject => value !== null && typeof value === 'object' && !Array.isArray(value);
const readJson = (dir: string, file: string) => JSON.parse(readFileSync(join(dir, file), 'utf-8'));

// Where a value is replaced: a path from the message, and the key that tells the same field apart
// in another fixture (same object type, same place, same key)
interface Site { path: (string | number)[]; key: string }

const sitesOf = (message: StixObject, call: FixtureCall): Site[] => {
  const sites: Site[] = [];
  const objectSites = (object: unknown, base: (string | number)[]) => {
    if (!isDict(object)) {
      return;
    }
    const objectType = JSON.stringify(object.type);
    Object.keys(object).filter((key) => key !== 'id' && key !== 'type').forEach((key) => {
      sites.push({ path: [...base, key], key: `${objectType} ${key}` });
    });
    const extensions = object.extensions;
    OPENCTI_EXTENSIONS.filter((extensionId) => isDict(extensions) && isDict(extensions[extensionId])).forEach((extensionId) => {
      Object.keys(extensions[extensionId]).filter((key) => key !== 'id' && key !== 'type').forEach((key) => {
        sites.push({ path: [...base, 'extensions', extensionId, key], key: `${objectType} ${extensionId} ${key}` });
      });
    });
  };
  if (call.message_type === 'event') {
    // The event itself (type, data, context...), then the object it carries
    Object.keys(message).forEach((key) => sites.push({ path: [key], key: `event ${key}` }));
    objectSites(message.data, ['data']);
  } else if (Array.isArray(message.objects)) {
    message.objects.forEach((object: unknown, index: number) => objectSites(object, ['objects', index]));
  }
  return sites;
};

const withValue = (message: StixObject, path: (string | number)[], value: unknown) => {
  const copy = structuredClone(message);
  let container: any = copy;
  path.slice(0, -1).forEach((step) => {
    container = container[step];
  });
  Object.defineProperty(container, path[path.length - 1], { value: structuredClone(value), writable: true, enumerable: true, configurable: true });
  return copy;
};

// Every fixture with its sites. A field already replaced in an earlier fixture (same object type,
// same place, same key) is skipped, but every fixture keeps at least its first site, so that each
// message shape (bundle, event, operation) is run
const fixtures = (readdirSync(FIXTURES_DIR, { recursive: true }) as string[])
  .filter((path) => existsSync(join(FIXTURES_DIR, path, 'input.json')))
  .map((path) => path.split(sep).join('/'))
  .sort();
const seenKeys = new Set<string>();
const cases = fixtures.map((fixture) => {
  const dir = join(FIXTURES_DIR, fixture);
  const call: FixtureCall = { ...DEFAULT_CALL, ...(existsSync(join(dir, 'call.json')) ? readJson(dir, 'call.json') : {}) };
  const message = readJson(dir, 'input.json');
  const all = sitesOf(message, call);
  const sites = all.filter((site, index) => index === 0 || !seenKeys.has(site.key));
  all.forEach((site) => seenKeys.add(site.key));
  return { fixture, dir, call, message, sites };
}).filter(({ sites }) => sites.length > 0);

// The first frame of the port in a stack: where the native error comes from
const portFrame = (error: Error) => (error.stack ?? '').split('\n').find((line) => line.includes('src/intake/') || line.includes('src/utils/'))?.trim() ?? 'unknown';

describe('Import conformance: wrongly typed fields give a Python outcome', () => {
  it('should replace fields of every fixture', () => {
    expect(cases.length).toBeGreaterThan(0);
  });
  it.each(cases.map((entry) => [entry.fixture, entry] as const))('%s', async (_, { dir, call, message, sites }) => {
    const failures: string[] = [];
    for (const site of sites) {
      for (const value of VALUES) {
        const label = `${site.path.join('.')} = ${JSON.stringify(value)}`;
        let calls = 0;
        const input = withValue(message, site.path, value);
        try {
          const result = await transformMessage(dir, call, input, false, () => {
            calls += 1;
            if (calls > CALL_BUDGET) {
              throw new Error(`more than ${CALL_BUDGET} calls`);
            }
          });
          const unknownOutcomes = result.items.filter(({ outcome }) => outcome !== 'transformed' && !PYTHON_OUTCOMES.has(outcome));
          if (unknownOutcomes.length > 0) {
            failures.push(`${label}: outcomes ${JSON.stringify(unknownOutcomes)}`);
          }
        } catch (error) {
          // transformMessage records a StixImportError as the bundle error: anything thrown is native
          const isPythonError = error instanceof StixImportError || error instanceof ImportClientError;
          failures.push(`${label}: ${isPythonError ? 'unexpected ' : ''}${(error as Error).name}: ${(error as Error).message} at ${portFrame(error as Error)}`);
        }
      }
    }
    expect(failures.length, `inputs without a Python outcome:\n${failures.slice(0, 30).join('\n')}`).toEqual(0);
  });
});
