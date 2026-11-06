import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, sep } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ChunkOperation } from '../../../src/graphql/chunk-executor';
import { captureBundle } from '../../../src/intake/chunk-capture/capture-bundle';
import { describeOperation } from '../../../src/intake/dry-intake/simulated-answers';
import { createImportContext } from '../../../src/intake/stix-import/context';
import { buildOperationGraph, operationKindOf } from '../../../src/intake/workerless/operation-graph';
import { RecordingClient } from '../import-conformance/import-conformance-client';
import { DEFAULT_CALL, FIXTURES_DIR } from '../import-conformance/import-conformance-utils';

// The operations of a push message as a dependency graph: an operation depends on the earlier
// operations that create or produce what it references (echo id, ||M|| member ref, plain STIX id).

const mutation = (root: string, sub?: string) => (sub
  ? `mutation M($id: ID!, $input: Any) { ${root}(id: $id) { ${sub}(input: $input) { id } } }`
  : `mutation M($input: Any) { ${root}(input: $input) { id } }`);
const op = (root: string, variables: Record<string, unknown>, ids: { object_id?: string; echo_id?: string } = {}, sub?: string): ChunkOperation => ({
  query: mutation(root, sub), variables, ...ids,
});

describe('Operation graph', () => {
  it('should link an operation to what produces its echo ids, member refs and plain STIX ids', () => {
    // pycti's import of a malware with an external reference read as a report: the reference and
    // the report are pre-created (echo ids), the malware created, then added to the report by the
    // STIX id pycti got back (no mark)
    const operations = [
      op('externalReferenceAdd', { input: { source_name: 'blog' } }, { echo_id: 'echo--1' }),
      op('reportAdd', { input: { name: 'blog', externalReferences: ['echo--1'] } }, { echo_id: 'echo--2' }),
      op('malwareAdd', { input: { name: 'm', stix_id: 'malware--1', createdBy: 'identity--1||M||' } }, { object_id: 'malware--1' }),
      op('reportEdit', { id: 'echo--2', input: { toId: 'malware--1', relationship_type: 'object' } }, { echo_id: 'echo--3' }, 'relationAdd'),
    ];
    const graph = buildOperationGraph(operations);
    expect(graph.nodes.map(({ deps, kind }) => ({ deps, kind }))).toEqual([
      { deps: [], kind: 'sequenced' },
      { deps: [0], kind: 'sequenced' },
      { deps: [], kind: 'sequenced' },
      { deps: [1, 2], kind: 'direct' },
    ]);
    // the author is a member of the bundle that no operation creates (its transformation failed)
    expect(graph.unproduced).toEqual(['identity--1']);
    expect(graph.dangling).toEqual([]);
    expect(graph.forward).toEqual([]);
  });

  it('should order a later operation on an object after its creation, and never link backwards in a cycle', () => {
    const operations = [
      op('reportAdd', { input: { stix_id: 'report--1', objects: ['note--1||M||'] } }, { object_id: 'report--1' }),
      op('noteAdd', { input: { stix_id: 'note--1', objects: ['report--1||M||'] } }, { object_id: 'note--1' }),
      op('stixCoreObjectEdit', { id: 'report--1', input: { key: 'description', value: ['x'] } }, { object_id: 'report--1' }, 'fieldPatch'),
      op('labelAdd', { input: { value: 'l' } }, { echo_id: 'echo--9' }),
      op('malwareAdd', { input: { stix_id: 'malware--2', objectLabel: ['echo--8'] } }, { object_id: 'malware--2' }),
    ];
    const graph = buildOperationGraph(operations);
    expect(graph.nodes.map(({ deps }) => deps)).toEqual([[], [0], [0], [], []]);
    // the report's soft ref to the note captured after it: not an edge
    expect(graph.forward).toEqual([{ index: 0, id: 'note--1' }]);
    expect(graph.dangling).toEqual(['echo--8']);
  });

  it('should treat as direct every operation that touches its targets outside the sequencer', () => {
    const kinds = [
      ['malwareAdd'], ['stixCoreRelationshipAdd'], ['stixSightingRelationshipAdd'], ['labelAdd'],
      ['stixRefRelationshipAdd'], ['reportEdit', 'relationAdd'], ['stixCyberObservableEdit', 'relationAdd'],
      ['stixCoreObjectEdit', 'fieldPatch'], ['stixDomainObjectEdit', 'delete'], ['workspaceDelete'],
    ].map(([root, sub]) => [sub ? `${root}.${sub}` : root, operationKindOf(op(root, {}, {}, sub))]);
    const hasCovered = op('stixCoreRelationshipAdd', { input: { relationship_type: 'has-covered', fromId: 'security-coverage--1||M||', toId: 'attack-pattern--1' } });
    expect(operationKindOf(hasCovered)).toEqual('direct');
    expect(Object.fromEntries(kinds)).toEqual({
      malwareAdd: 'sequenced',
      stixCoreRelationshipAdd: 'sequenced',
      stixSightingRelationshipAdd: 'sequenced',
      labelAdd: 'sequenced',
      stixRefRelationshipAdd: 'direct',
      'reportEdit.relationAdd': 'direct',
      'stixCyberObservableEdit.relationAdd': 'direct',
      'stixCoreObjectEdit.fieldPatch': 'direct',
      'stixDomainObjectEdit.delete': 'direct',
      workspaceDelete: 'direct',
    });
  });
});

// On the import conformance fixtures: what the split marks as in the bundle becomes an edge
// (plus the worker's multi-object bundles, where the members reference each other)
const CHUNK_FIXTURES_DIR = join(__dirname, '../../../../../opencti-worker/tests/data/chunk-capture-fixtures');
const fixturesOf = (dir: string) => (readdirSync(dir, { recursive: true }) as string[])
  .filter((path) => path.endsWith(`${sep}input.json`) || path === 'input.json')
  .map((path) => join(dir, path.slice(0, -'input.json'.length)))
  .sort();
const fixtures = [...fixturesOf(FIXTURES_DIR), ...fixturesOf(CHUNK_FIXTURES_DIR)];
const readJson = (dir: string, file: string) => JSON.parse(readFileSync(join(dir, file), 'utf-8'));
const captureOf = async (dir: string) => {
  const call = { ...DEFAULT_CALL, ...(existsSync(join(dir, 'call.json')) ? readJson(dir, 'call.json') : {}) };
  const context = createImportContext(new RecordingClient(dir, false), { error: () => {}, warn: () => {} }, { now: new Date(call.now) });
  return captureBundle(context, readJson(dir, 'input.json'), call.update, call.types, 24).then((captured) => captured.operations, () => null);
};

describe('Operation graph on the import conformance fixtures', () => {
  it('should resolve every echo id and turn every marked member ref into an edge', async () => {
    const roots = new Map<string, string>();
    let checked = 0;
    let captured = 0;
    for (let f = 0; f < fixtures.length; f += 1) {
      const operations = await captureOf(fixtures[f]);
      if (operations) {
        captured += 1;
        const graph = buildOperationGraph(operations);
        const name = fixtures[f];
        expect(graph.dangling, name).toEqual([]);
        // pycti creates a sub-object once per message: one producer per echo id
        const echoes = operations.filter((operation) => operation.echo_id).map((operation) => operation.echo_id);
        expect(new Set(echoes).size, name).toEqual(echoes.length);
        const firstOf = new Map<string, number>();
        operations.forEach((operation, index) => {
          if (operation.object_id && !firstOf.has(operation.object_id)) firstOf.set(operation.object_id, index);
        });
        graph.nodes.forEach(({ operation, kind, deps }, index) => {
          const { root, sub } = describeOperation(operation.query);
          roots.set(sub ? `${root}.${sub}` : root, kind);
          deps.forEach((dep) => expect(dep, name).toBeLessThan(index));
          const marked = [...JSON.stringify(operation.variables ?? {}).matchAll(/"([^"]+)\|\|M\|\|"/g)].map((match) => match[1]);
          marked.filter((id) => firstOf.has(id)).forEach((id) => {
            const producer = firstOf.get(id) as number;
            if (producer < index) expect(deps, `${name}: ${id}`).toContain(producer);
            else if (producer > index) expect(graph.forward, `${name}: ${id}`).toContainEqual({ index, id });
            checked += 1;
          });
        });
      }
    }
    expect(captured).toBeGreaterThan(fixtures.length / 2);
    expect(checked).toBeGreaterThan(0);
    // every kind of operation the import produces, as the intake will release it
    expect(Object.fromEntries([...roots.entries()].sort())).toMatchSnapshot();
  });
});
