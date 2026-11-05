import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, sep } from 'node:path';
import { type FieldNode, Kind, type OperationDefinitionNode, parse, print, validate } from 'graphql';
import { describe, expect, it } from 'vitest';
import type { ChunkOperation } from '../../../src/graphql/chunk-executor';
import { pruneResponseConnections } from '../../../src/graphql/chunk-document-prune';
import '../../../src/modules/index';
import createSchema from '../../../src/graphql/schema';
import { captureBundle } from '../../../src/intake/chunk-capture/capture-bundle';
import { ECHO_PREFIX, NotChunkableError } from '../../../src/intake/chunk-capture/capture-client';
import type { ChunkContent } from '../../../src/intake/chunk-capture/chunks';
import { describeOperation } from '../../../src/intake/dry-intake/simulated-answers';
import { createImportContext } from '../../../src/intake/stix-import/context';
import { RecordingClient } from '../import-conformance/import-conformance-client';
import { ACCEPTED_DIFFERENCES_FILE, DEFAULT_CALL, FIXTURES_DIR } from '../import-conformance/import-conformance-utils';

// The worker-less intake builds the worker's chunks: the goldens are the chunks the worker
// publishes for each import conformance fixture, plus multi-object bundles of its own
// (opencti-worker/tests/chunk_capture_goldens.py). The fixtures the worker does not send as
// chunks (stream events, files, messages it cannot split) are listed in excluded.json: the port
// must refuse them too.

const WORKER_DATA_DIR = join(__dirname, '../../../../../opencti-worker/tests/data');
const GOLDENS_DIR = join(WORKER_DATA_DIR, 'chunk-capture');
const CHUNK_FIXTURES_DIR = join(WORKER_DATA_DIR, 'chunk-capture-fixtures');
const CHUNK_FIXTURES_PREFIX = 'chunk-capture/';
const CHUNK_SIZES = ['3', '24'];

const EXCLUDED: Record<string, string> = JSON.parse(readFileSync(join(GOLDENS_DIR, 'excluded.json'), 'utf-8'));
// The port differs from pycti on these on purpose (pycti defects): their operations differ too
const ACCEPTED_DIFFERENCES: Record<string, unknown> = JSON.parse(readFileSync(ACCEPTED_DIFFERENCES_FILE, 'utf-8'));

// Where the worker's capture and the port part, with the port's behaviour asserted instead
const CAPTURE_DIFFERENCES: Record<string, string> = {
  // pycti reads the fieldPatch of the echo it gets for the description patch (KeyError): the
  // worker drops the object there and never uploads its file. The port does not read that answer,
  // goes on to the file upload, and a file cannot travel in a chunk.
  'ops/patch/task-external-reference.ext': 'not chunkable: a file in the variables',
};

const fixturesOf = (dir: string, prefix: string) => (readdirSync(dir, { recursive: true }) as string[])
  .filter((path) => path.endsWith(`${sep}input.json`) || path === 'input.json')
  .map((path) => ({ name: `${prefix}${path.slice(0, -'/input.json'.length).split(sep).join('/')}`, dir: join(dir, path.slice(0, -'/input.json'.length)) }))
  .sort((a, b) => a.name.localeCompare(b.name));
const FIXTURES = [...fixturesOf(FIXTURES_DIR, ''), ...fixturesOf(CHUNK_FIXTURES_DIR, CHUNK_FIXTURES_PREFIX)];

// The documents of the captured operations, for the pruning check
const CAPTURED_DOCUMENTS = new Set<string>();
const PRODUCER_DOCUMENTS = new Set<string>();

const readJson = (dir: string, file: string) => JSON.parse(readFileSync(join(dir, file), 'utf-8'));

// Echo ids are random: named by order of first production, as the goldens
const namedEchoes = (chunks: ChunkContent[]) => {
  const names = new Map<string, string>();
  chunks.forEach((chunk) => chunk.operations.forEach((operation) => {
    if (operation.echo_id && !names.has(operation.echo_id)) {
      names.set(operation.echo_id, `${ECHO_PREFIX}${names.size + 1}`);
    }
  }));
  const rename = (value: unknown): unknown => {
    if (typeof value === 'string') {
      return names.get(value) ?? value;
    }
    if (Array.isArray(value)) {
      return value.map(rename);
    }
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, rename(item)]));
    }
    return value;
  };
  return chunks.map((chunk) => rename(chunk) as ChunkContent);
};

// Each run of consecutive producers sorted by echo id (the worker adds them in a set's order)
const canonicalProducers = (operations: ChunkOperation[]) => {
  const result: ChunkOperation[] = [];
  let run: ChunkOperation[] = [];
  const flush = () => {
    result.push(...run.sort((a, b) => (a.echo_id as string).localeCompare(b.echo_id as string)));
    run = [];
  };
  operations.forEach((operation) => {
    if (operation.echo_id) {
      run.push(operation);
    } else {
      flush();
      result.push(operation);
    }
  });
  flush();
  return result;
};

// The documents are the port's, not pycti's text: compared as operations
const comparable = (chunks: ChunkContent[]) => chunks.map((chunk) => ({
  work_objects: chunk.work_objects,
  operations: canonicalProducers(chunk.operations).map(({ query, variables, object_id: objectId, echo_id: echoId }) => {
    const { op, name, root, sub } = describeOperation(query);
    return { op, name, root, sub, variables, object_id: objectId ?? null, echo_id: echoId ?? null };
  }),
}));

const capture = async (dir: string, size: number) => {
  const call = { ...DEFAULT_CALL, ...(existsSync(join(dir, 'call.json')) ? readJson(dir, 'call.json') : {}) };
  const context = createImportContext(new RecordingClient(dir, false), { error: () => {}, warn: () => {} }, { now: new Date(call.now) });
  return captureBundle(context, readJson(dir, 'input.json'), call.update, call.types, size);
};

describe('Chunk capture conformance with the worker', () => {
  it('should cover every fixture with a golden or an exclusion', () => {
    const goldens = (readdirSync(GOLDENS_DIR, { recursive: true }) as string[])
      .filter((path) => path.endsWith('.json') && path !== 'excluded.json')
      .map((path) => path.slice(0, -'.json'.length).split(sep).join('/'));
    expect([...goldens, ...Object.keys(EXCLUDED)].sort()).toEqual(FIXTURES.map(({ name }) => name).sort());
  });

  // The platform's splitter takes some malformed messages pycti's refuses (accepted differences)
  it.each(FIXTURES.filter(({ name }) => name in EXCLUDED && !(name in ACCEPTED_DIFFERENCES)).map(({ name, dir }) => [name, dir]))('should refuse %s as the worker does', async (name, dir) => {
    const error = await capture(dir, 24).then(() => null, (failure) => failure);
    // A stream event is not a bundle: the intake routes it before any capture
    if (EXCLUDED[name].startsWith('stream event')) {
      return;
    }
    expect(error, EXCLUDED[name]).not.toBeNull();
    if (EXCLUDED[name].startsWith('split error')) {
      expect(error).not.toBeInstanceOf(NotChunkableError);
    } else {
      expect(error).toBeInstanceOf(NotChunkableError);
    }
  });

  it.each(Object.keys(CAPTURE_DIFFERENCES).map((name) => [name, join(FIXTURES_DIR, name)]))('should refuse %s where the worker drops the object', async (name, dir) => {
    const error = await capture(dir, 24).then(() => null, (failure) => failure);
    expect(error, CAPTURE_DIFFERENCES[name]).toBeInstanceOf(NotChunkableError);
  });

  it.each(FIXTURES.filter(({ name }) => !(name in EXCLUDED) && !(name in ACCEPTED_DIFFERENCES) && !(name in CAPTURE_DIFFERENCES)).map(({ name, dir }) => [name, dir]))('should build the worker chunks of %s', async (name, dir) => {
    const golden = JSON.parse(readFileSync(join(GOLDENS_DIR, `${name}.json`), 'utf-8'));
    for (const size of CHUNK_SIZES) {
      const captured = await capture(dir, Number(size));
      expect(captured.dangling, 'echoes without producer').toEqual([]);
      expect(captured.incompatible).toEqual(golden.incompatible);
      expect(comparable(namedEchoes(captured.chunks)), `chunk size ${size}`).toEqual(comparable(golden.chunks[size]));
      // A create without STIX id gets an echo (edits and deletes too): a producer is one whose
      // echo another operation references
      const operations = captured.chunks.flatMap((chunk) => chunk.operations);
      const referenced = JSON.stringify(operations.filter((operation) => !operation.echo_id).map((operation) => operation.variables));
      operations.forEach((operation) => {
        CAPTURED_DOCUMENTS.add(operation.query);
        if (operation.echo_id && referenced.includes(`"${operation.echo_id}"`)) {
          PRODUCER_DOCUMENTS.add(operation.query);
        }
      });
    }
  });

  // The manager prunes the connections pycti selects in its answers (indicatorAdd observables,
  // stixCyberObservableAdd indicators: the b400 ES rejections): it must find them in the port's
  // documents too, and the pruned documents must stay valid
  it('should leave no connection in the pruned documents of the port', () => {
    expect(CAPTURED_DOCUMENTS.size).toBeGreaterThan(0);
    const schema = createSchema();
    const pruned = [...CAPTURED_DOCUMENTS].map((document) => pruneResponseConnections(parse(document)));
    expect(pruned.filter((document) => print(document).includes('edges')).map(print)).toEqual([]);
    expect(pruned.flatMap((document) => validate(schema, document).map((error) => error.message))).toEqual([]);
    expect([...CAPTURED_DOCUMENTS].some((document) => document.includes('edges')), 'a document with a connection to prune').toBe(true);
    // A producer run first gives the manager the real id of its echo: data[root].id
    // (chunkIntakeManager.ts, the legacy path of the producers without a standard id)
    expect(PRODUCER_DOCUMENTS.size).toBeGreaterThan(0);
    const withoutId = [...PRODUCER_DOCUMENTS].filter((document) => {
      const operation = pruneResponseConnections(parse(document)).definitions.find((definition) => definition.kind === Kind.OPERATION_DEFINITION) as OperationDefinitionNode;
      const root = operation.selectionSet.selections[0] as FieldNode;
      return !root.selectionSet?.selections.some((selection) => selection.kind === Kind.FIELD && selection.name.value === 'id');
    });
    expect(withoutId, 'producer documents without the id of their answer').toEqual([]);
  });
});
