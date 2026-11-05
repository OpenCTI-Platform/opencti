import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { responseId } from './import-conformance-client';
import { FIXTURES_DIR } from './import-conformance-utils';

// The goldens recorded by client-python answer each mutation with a deterministic id that later
// calls reuse (labels, external references, ...). Any importer replayed against the goldens must
// compute the same ids: this test recomputes them on the platform side.
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface GoldenCall {
  seq: number;
  op: 'query' | 'mutation';
  root: string;
  sub: string | null;
  variables: unknown;
}

const collectStrings = (value: unknown): string[] => {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(collectStrings);
  if (value && typeof value === 'object') return Object.values(value).flatMap(collectStrings);
  return [];
};

const fixtures = (readdirSync(FIXTURES_DIR, { recursive: true }) as string[])
  .filter((path) => existsSync(join(FIXTURES_DIR, path, 'expected.json')))
  .sort();

describe('Import conformance ids', () => {
  let reusedIds = 0;
  it.each(fixtures)('%s: every id a call reuses is an earlier answer or comes from the fixture', (fixture) => {
    // The fixture's own ids: the bundle, the envelope and import parameters, the world
    const input = ['input.json', 'call.json', 'world.json']
      .filter((file) => existsSync(join(FIXTURES_DIR, fixture, file)))
      .map((file) => readFileSync(join(FIXTURES_DIR, fixture, file), 'utf-8'))
      .join('\n');
    const calls: GoldenCall[] = JSON.parse(readFileSync(join(FIXTURES_DIR, fixture, 'expected.json'), 'utf-8')).calls;
    const answered = new Set<string>();
    calls.forEach((call) => {
      collectStrings(call.variables).filter((value) => UUID_PATTERN.test(value)).forEach((value) => {
        if (answered.has(value)) {
          reusedIds += 1;
        } else {
          expect(input.includes(value), `call ${call.seq}: ${value} is neither an earlier answer nor in the fixture`).toBe(true);
        }
      });
      if (call.op === 'mutation') {
        answered.add(responseId(call.root, call.sub, call.variables));
      }
    });
  });
  it('should check at least one reused id', () => {
    expect(reusedIds).toBeGreaterThan(0);
  });
});
