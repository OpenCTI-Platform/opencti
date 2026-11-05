import { describe, expect, it } from 'vitest';
import type { ChunkOperation } from '../../../src/graphql/chunk-executor';
import { captureBundle } from '../../../src/intake/chunk-capture/capture-bundle';
import { type CaptureWindow, ECHO_PREFIX } from '../../../src/intake/chunk-capture/capture-client';
import { buildChunks, chunkContents } from '../../../src/intake/chunk-capture/chunks';
import { CaptureCache, purgeCaptureWindow } from '../../../src/intake/chunk-capture/capture-cache';
import { createImportContext, getInCache, type ImportContext, setInCache } from '../../../src/intake/stix-import/context';
import type { ImportClient } from '../../../src/intake/stix-import/types';
import { FIXTURES_DIR } from '../import-conformance/import-conformance-utils';
import { RecordingClient } from '../import-conformance/import-conformance-client';

// The intake captures several messages at once on one transformation context (one per draft,
// its cache shared): an echo is only valid in the message that created it.

const malware = (index: number) => ({
  type: 'malware',
  spec_version: '2.1',
  id: `malware--00000000-0000-4000-8000-00000000000${index}`,
  created: '2024-01-01T00:00:00.000Z',
  modified: '2024-01-01T00:00:00.000Z',
  name: `Malware ${index}`,
  is_family: true,
  labels: ['shared-label'],
});
const bundleOf = (...objects: unknown[]) => ({ type: 'bundle', id: 'bundle--00000000-0000-4000-8000-000000000000', objects });

const echoRefs = (operations: ChunkOperation[]) => JSON.stringify(operations.filter((operation) => !operation.echo_id).map((operation) => operation.variables))
  .match(/echo--[0-9a-f-]{36}/g) ?? [];

describe('Chunk capture windows', () => {
  it('should give each message its own producers when they run interleaved on one context', async () => {
    // Every read waits a turn so that the two captures interleave
    const recording = new RecordingClient(FIXTURES_DIR, false);
    const reads: ImportClient = { query: async (document, variables) => {
      await new Promise((resolve) => {
        setTimeout(resolve, 1);
      });
      return recording.query(document, variables);
    } };
    const context = createImportContext(reads, { error: () => {}, warn: () => {} });
    const [first, second] = await Promise.all([
      captureBundle(context, bundleOf(malware(1)), false, null, 24),
      captureBundle(context, bundleOf(malware(2)), false, null, 24),
    ]);
    [first, second].forEach((captured) => {
      const operations = captured.chunks.flatMap((chunk) => chunk.operations);
      const produced = new Set(operations.filter((operation) => operation.echo_id).map((operation) => operation.echo_id));
      expect(captured.dangling).toEqual([]);
      expect(produced.size, 'the label producer').toEqual(1);
      expect(echoRefs(operations).every((echo) => produced.has(echo)), 'refs to its own echoes only').toBe(true);
    });
    const firstEcho = first.chunks[0].operations.find((operation) => operation.echo_id)?.echo_id;
    const secondEcho = second.chunks[0].operations.find((operation) => operation.echo_id)?.echo_id;
    expect(firstEcho).not.toEqual(secondEcho);
    // Both windows closed: no echo left in the shared cache
    expect([...context.cache.values()].filter((value) => typeof value?.id === 'string' && value.id.startsWith(ECHO_PREFIX))).toEqual([]);
  });

  it('should answer an echo only to the message that created it, and drop it at its end', () => {
    const context = createImportContext(new RecordingClient(FIXTURES_DIR, false), { error: () => {}, warn: () => {} });
    const windowOf = (echo: string): CaptureWindow => ({ echoes: new Set([echo]), keys: new Set() });
    const first = windowOf('echo--first');
    const second = windowOf('echo--second');
    const inWindow = (window: CaptureWindow): ImportContext => ({ ...context, cache: new CaptureCache(context.cache, window) });
    setInCache(inWindow(first), 'label', { id: 'echo--first' });
    expect(getInCache(inWindow(first), 'label')).toEqual({ id: 'echo--first' });
    expect(getInCache(inWindow(second), 'label'), 'an echo of another message').toBeNull();
    // The second message stores its own echo under the same key: the first one's end keeps it
    setInCache(inWindow(second), 'label', { id: 'echo--second' });
    purgeCaptureWindow(context.cache, first);
    expect(getInCache(inWindow(second), 'label')).toEqual({ id: 'echo--second' });
    purgeCaptureWindow(context.cache, second);
    expect(context.cache.size).toEqual(0);
  });

  it('should give a message its own producers while another one holds echoes in the shared cache', async () => {
    // One context for the life of the intake (per draft). The first message stops on a read (an
    // open vocabulary) after its first object stored echoes; the second runs meanwhile.
    const author = { type: 'identity', spec_version: '2.1', id: 'identity--00000000-0000-4000-8000-0000000000a1', name: 'Author', identity_class: 'organization' };
    const subObjects = {
      created_by_ref: author.id,
      object_marking_refs: ['marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9'],
      external_references: [{ source_name: 'shared-source', url: 'https://example.com/shared', external_id: 'S-1' }],
      kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }],
    };
    const first = bundleOf(author, { ...malware(1), ...subObjects }, { ...malware(3), ...subObjects, malware_types: ['ransomware'] });
    const second = bundleOf(author, { ...malware(2), ...subObjects });
    const recording = new RecordingClient(FIXTURES_DIR, false);
    let releaseFirst: () => void = () => {};
    const firstOnHold = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let held: () => void = () => {};
    const firstHeld = new Promise<void>((resolve) => {
      held = resolve;
    });
    let holding = true;
    const reads: ImportClient = { query: async (document, variables) => {
      if (holding && document.includes('vocabularies')) {
        holding = false;
        held();
        await firstOnHold;
      }
      return recording.query(document, variables);
    } };
    const context = createImportContext(reads, { error: () => {}, warn: () => {} });
    const firstCapture = captureBundle(context, first, false, null, 24);
    await firstHeld;
    const echoesHeld = [...context.cache.values()].filter((value) => typeof value?.id === 'string' && value.id.startsWith(ECHO_PREFIX));
    expect(echoesHeld.length, 'echoes of the first message in the shared cache').toBeGreaterThan(0);
    const secondCaptured = await captureBundle(context, second, false, null, 24);
    releaseFirst();
    const firstCaptured = await firstCapture;
    [firstCaptured, secondCaptured].forEach((captured) => {
      const operations = captured.chunks.flatMap((chunk) => chunk.operations);
      const produced = new Set(operations.filter((operation) => operation.echo_id).map((operation) => operation.echo_id));
      expect(captured.dangling).toEqual([]);
      expect(echoRefs(operations).length).toBeGreaterThan(0);
      expect(echoRefs(operations).every((echo) => produced.has(echo)), 'refs to its own echoes only').toBe(true);
    });
    expect([...context.cache.values()].filter((value) => typeof value?.id === 'string' && value.id.startsWith(ECHO_PREFIX))).toEqual([]);
  });

  it('should keep in the cache what a message stored with a STIX id', async () => {
    const context = createImportContext(new RecordingClient(FIXTURES_DIR, false), { error: () => {}, warn: () => {} });
    await captureBundle(context, bundleOf(malware(1)), false, null, 24);
    expect([...context.cache.values()].some((value) => value?.id === 'malware--00000000-0000-4000-8000-000000000001')).toBe(true);
  });

  it('should repeat in each chunk the producers its operations reference', () => {
    const producer: ChunkOperation = { query: 'mutation LabelAdd', variables: { input: { value: 'a' } }, object_id: null, echo_id: 'echo--p' };
    const consumer = (index: number): ChunkOperation => ({ query: 'mutation MalwareAdd', variables: { input: { objectLabel: ['echo--p'] } }, object_id: `malware--${index}` });
    const dangling = new Set<string>();
    const chunks = buildChunks([producer, consumer(1), consumer(2), consumer(3)], 2, dangling);
    expect(chunks.map((chunk) => chunk.map((operation) => operation.echo_id ?? operation.object_id))).toEqual([
      ['echo--p', 'malware--1', 'malware--2'],
      ['echo--p', 'malware--3'],
    ]);
    expect([...dangling]).toEqual([]);
    buildChunks([consumer(1)], 2, dangling);
    expect([...dangling]).toEqual(['echo--p']);
  });

  it('should never mix dependency levels in a chunk, and repeat an earlier level\'s producer where referenced', () => {
    const producer: ChunkOperation = { query: 'mutation LabelAdd', variables: { input: { value: 'a' } }, object_id: null, echo_id: 'echo--p' };
    const author: ChunkOperation = { query: 'mutation IdentityAdd', variables: { input: {} }, object_id: 'identity--1' };
    const indicator = (index: number): ChunkOperation => ({ query: 'mutation IndicatorAdd', variables: { input: { createdBy: 'identity--1', objectLabel: ['echo--p'] } }, object_id: `indicator--${index}` });
    const operations = [producer, author, indicator(1), indicator(2)];
    const chunks = chunkContents(operations, 24, undefined, [0, 0, 1, 1]);
    expect(chunks.map((chunk) => ({ level: chunk.level, ids: chunk.operations.map((operation) => operation.echo_id ?? operation.object_id) }))).toEqual([
      { level: 0, ids: ['echo--p', 'identity--1'] },
      { level: 1, ids: ['echo--p', 'indicator--1', 'indicator--2'] },
    ]);
    // without levels: the worker's chunk
    expect(chunkContents(operations, 24).map((chunk) => chunk.operations.length)).toEqual([4]);
  });
});
