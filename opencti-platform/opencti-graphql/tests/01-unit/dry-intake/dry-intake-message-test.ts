import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import createSchema from '../../../src/graphql/schema';
import { getVocabulariesCategories } from '../../../src/modules/vocabulary/vocabulary-utils';
import { createImportContext, type ImportContext } from '../../../src/intake/stix-import/context';
import { DryClient } from '../../../src/intake/dry-intake/dry-client';
import { type DryIntakeDeps, type DryRung, processDryMessage } from '../../../src/intake/dry-intake/dry-intake-message';

const malware = { type: 'malware', spec_version: '2.1', id: 'malware--10000000-0000-4000-8000-000000000001', name: 'm', is_family: true };
const identity = { type: 'identity', spec_version: '2.1', id: 'identity--10000000-0000-4000-8000-000000000002', name: 'i', identity_class: 'organization' };
const relationship = {
  type: 'relationship',
  spec_version: '2.1',
  id: 'relationship--10000000-0000-4000-8000-000000000003',
  relationship_type: 'targets',
  source_ref: malware.id,
  target_ref: identity.id,
};
const bundle = (...objects: unknown[]) => ({ type: 'bundle', id: 'bundle--10000000-0000-4000-8000-000000000000', objects });
// A push message as pycti publishes it: no type, the bundle in base64
const message = (content: unknown, envelope: Record<string, unknown> = {}) => JSON.stringify({
  applicant_id: null,
  content: Buffer.from(JSON.stringify(content)).toString('base64'),
  update: false,
  ...envelope,
});

const depsFor = (rung: DryRung, client = new DryClient({ vocabularyCategories: getVocabulariesCategories() })) => {
  const contexts = new Map<string, ImportContext>();
  const deps: DryIntakeDeps & { contexts: Map<string, ImportContext> } = {
    rung,
    client,
    contexts,
    contextFor: (draftId) => {
      const context = contexts.get(draftId) ?? createImportContext(client, { error: () => {}, warn: () => {} }, { draftId });
      contexts.set(draftId, context);
      return context;
    },
  };
  return deps;
};

describe('Dry intake: one push message up to its rung', () => {
  it('should only ack at the ack rung, without decoding', async () => {
    const result = await processDryMessage('not even json', depsFor('ack'));
    expect(result).toEqual({ ack: true, failedStage: null, defect: false, objects: 0, parts: 0, operations: 0, outcomes: {}, timings: {} });
  });
  it('should split a multi-object bundle, and count the parts', async () => {
    const result = await processDryMessage(message(bundle(malware, identity, relationship)), depsFor('split'));
    expect(result).toMatchObject({ ack: true, failedStage: null, objects: 3, parts: 3, operations: 0 });
    expect(Object.keys(result.timings).sort()).toEqual(['decode', 'split']);
  });
  it('should split a bundle flagged no_split too (the worker splits it inside its import), not a single-object bundle', async () => {
    const unknown = { type: 'x-unknown', id: 'x-unknown--10000000-0000-4000-8000-000000000009' };
    expect(await processDryMessage(message(bundle(malware, unknown), { no_split: true }), depsFor('split'))).toMatchObject({ objects: 2, parts: 1 });
    // The splitter would give one part for this malware: a single-object bundle is not split
    expect(await processDryMessage(message(bundle(malware)), depsFor('split'))).toMatchObject({ objects: 1, parts: 0 });
  });
  it('should count the objects the split sets aside at the split rung', async () => {
    const unknown = { type: 'x-unknown', id: 'x-unknown--10000000-0000-4000-8000-000000000009' };
    const result = await processDryMessage(message(bundle(malware, unknown)), depsFor('split'));
    expect(result).toMatchObject({ ack: true, objects: 2, parts: 1, outcomes: { set_aside: 1 } });
  });
  it('should nack a bundle the split refuses at the split rung', async () => {
    const result = await processDryMessage(message(bundle(null, null)), depsFor('split'));
    expect(result).toMatchObject({ ack: false, failedStage: 'split', defect: false, objects: 2 });
  });
  it('should nack what the worker refuses: not JSON, not base64 JSON, no objects, unknown type', async () => {
    // push_handler.py: data.get("type", "bundle") gives None for an explicit null, then "Unsupported event type";
    // base64.b64decode refuses a content that is not a string, .decode("utf-8") an invalid byte sequence
    const invalidUtf8 = Buffer.concat([Buffer.from('{"type":"bundle","objects":[{"name":"'), Buffer.from([0xff, 0xfe]), Buffer.from('"}]}')]).toString('base64');
    const refused = [
      '{',
      JSON.stringify({ content: 'not base64 json' }),
      message(bundle()),
      message(bundle(malware), { type: 'other' }),
      message(bundle(malware), { type: null }),
      // The bytes of a valid bundle, as an array: Buffer.from would read them, b64decode refuses them
      JSON.stringify({ content: [...Buffer.from(JSON.stringify(bundle(malware)))] }),
      JSON.stringify({ content: invalidUtf8 }),
    ];
    for (const body of refused) {
      const result = await processDryMessage(body, depsFor('map'));
      expect(result).toMatchObject({ ack: false, failedStage: 'decode', objects: 0 });
    }
  });
  it('should map a bundle into operations, in the draft of the message', async () => {
    const deps = depsFor('map');
    const result = await processDryMessage(message(bundle(malware, identity, relationship), { draft_id: 'draft-1' }), deps);
    expect(result).toMatchObject({ ack: true, failedStage: null, defect: false, objects: 3, outcomes: { transformed: 3 } });
    expect(result.operations).toBeGreaterThanOrEqual(3);
    expect(Object.keys(result.timings).sort()).toEqual(['decode', 'map']);
    expect([...deps.contexts.keys()]).toEqual(['draft-1']);
  });
  it('should count the objects of the bundle received, and the objects the split sets aside', async () => {
    const unknown = { type: 'x-unknown', id: 'x-unknown--10000000-0000-4000-8000-000000000009' };
    const result = await processDryMessage(message(bundle(malware, unknown)), depsFor('map'));
    expect(result).toMatchObject({ ack: true, objects: 2, parts: 0, outcomes: { transformed: 1, set_aside: 1 } });
  });
  it('should nack a bundle the transformation refuses as a whole at the map rung', async () => {
    const result = await processDryMessage(message(bundle(null)), depsFor('map'));
    expect(result).toMatchObject({ ack: false, failedStage: 'map', defect: false, objects: 1 });
  });
  it('should map a stream event as the worker does (update forced)', async () => {
    const client = new DryClient({ vocabularyCategories: getVocabulariesCategories() });
    const updates: unknown[] = [];
    const query = client.query.bind(client);
    client.query = async (document, variables) => {
      updates.push((variables as any)?.input?.update);
      return query(document, variables);
    };
    const event = { type: 'update', data: malware };
    const result = await processDryMessage(message(event, { type: 'event', update: false }), depsFor('map', client));
    expect(result).toMatchObject({ ack: true, objects: 1, outcomes: { transformed: 1 } });
    expect(updates).toContain(true);
    expect(updates).not.toContain(false);
  });
  it('should nack a stream event of an operation the worker does not handle', async () => {
    const result = await processDryMessage(message({ type: 'unknown', data: malware }, { type: 'event' }), depsFor('map'));
    expect(result).toMatchObject({ ack: false, failedStage: 'decode' });
  });
  it('should give a refused operation the outcome pycti gives a GraphQL error at the validate rung', async () => {
    const client = new DryClient({ vocabularyCategories: getVocabulariesCategories() }, createSchema());
    const valid = await processDryMessage(message(bundle(malware)), depsFor('validate', client));
    expect(valid).toMatchObject({ ack: true, outcomes: { transformed: 1 } });
    // The String scalar refuses a number: pycti sends it as is
    const refused = await processDryMessage(message(bundle({ ...malware, name: 12 })), depsFor('validate', client));
    expect(refused).toMatchObject({ ack: true, defect: false, outcomes: { ValueError: 1 } });
  });
  // push_handler.py:271-275: an unmanaged exception nacks the message
  it('should count a native error of the transformation as a defect, nacked as the worker does', async () => {
    const client = new DryClient({ vocabularyCategories: getVocabulariesCategories() });
    client.query = async () => {
      throw new TypeError('defect');
    };
    const result = await processDryMessage(message(bundle(malware)), depsFor('map', client));
    expect(result).toMatchObject({ ack: false, defect: true, failedStage: 'map' });
  });
  // The manager shares one client between all messages: each message counts its own operations
  it('should count the operations of each message on a shared client', async () => {
    const deps = depsFor('map');
    const first = await processDryMessage(message(bundle(malware, identity, relationship)), deps);
    const alone = await processDryMessage(message(bundle(malware, identity, relationship)), depsFor('map'));
    const second = await processDryMessage(message(bundle(malware, identity, relationship)), deps);
    expect(first.operations).toEqual(alone.operations);
    expect(second.operations).toBeGreaterThan(0);
    expect(second.operations).toBeLessThanOrEqual(first.operations);
    expect(deps.client.operations).toEqual(first.operations + second.operations);
  });
  it('should give the update flag and the entity types of the envelope to the transformation', async () => {
    const client = new DryClient({ vocabularyCategories: getVocabulariesCategories() });
    const updates: unknown[] = [];
    const query = client.query.bind(client);
    client.query = async (document, variables) => {
      updates.push((variables as any)?.input?.update);
      return query(document, variables);
    };
    await processDryMessage(message(bundle(malware), { update: true }), depsFor('map', client));
    expect(updates).toContain(true);
    expect(updates).not.toContain(false);
    // entities_types: an object of another type is not imported (pycti's types filter)
    const filtered = await processDryMessage(message(bundle(malware, identity), { entities_types: ['Identity'] }), depsFor('map'));
    const all = await processDryMessage(message(bundle(malware, identity)), depsFor('map'));
    expect(filtered.operations).toBeLessThan(all.operations);
  });
});
