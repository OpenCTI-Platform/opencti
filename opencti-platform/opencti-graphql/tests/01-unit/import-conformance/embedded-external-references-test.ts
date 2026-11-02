import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { getVocabulariesCategories } from '../../../src/modules/vocabulary/vocabulary-utils';
import { createImportContext } from '../../../src/intake/stix-import/context';
import { extractEmbeddedRelationships } from '../../../src/intake/stix-import/embedded';
import { externalReferenceId } from '../../../src/intake/stix-import/sub-objects';
import type { ImportClient, StixObject } from '../../../src/intake/stix-import/types';
import { DryClient } from '../../../src/intake/dry-intake/dry-client';
import { describeOperation } from '../../../src/intake/dry-intake/simulated-answers';

// pycti creates an external reference only when external_reference.generate_id is not None: a
// url, or a source name and an external id. The splitter already drops the others from
// external_references, so the conformance fixtures never reach this test through it.

const createdReferences = async (object: StixObject) => {
  const dryClient = new DryClient({ vocabularyCategories: getVocabulariesCategories() });
  const inputs: unknown[] = [];
  const client: ImportClient = {
    query: (document, variables) => {
      if (describeOperation(document).root === 'externalReferenceAdd') {
        inputs.push((variables as { input: StixObject }).input);
      }
      return dryClient.query(document, variables);
    },
  };
  const context = createImportContext(client, { error: () => {}, warn: () => {} }, { now: new Date('2026-01-01T00:00:00Z') });
  const embedded = await extractEmbeddedRelationships(context, object);
  return { inputs, ids: embedded.external_references };
};

const REFERENCES = [
  { source_name: 'name-only' },
  { url: 'https://example.com/a' },
  { external_id: 'id-only' },
  { source_name: 'source', external_id: 'T1' },
  { source_name: 'source', external_id: null, url: null },
];

describe('extractEmbeddedRelationships: external references without an id are skipped', () => {
  it.each(['external_references', 'x_opencti_external_references'])('should create only the references with an id from %s', async (key) => {
    const { inputs, ids } = await createdReferences({ id: 'malware--refs', type: 'malware', [key]: REFERENCES });
    expect(inputs.map((input) => [(input as StixObject).url, (input as StixObject).external_id])).toEqual([['https://example.com/a', null], [null, 'T1']]);
    expect(ids).toHaveLength(2);
  });

  it.each(['external_references', 'x_opencti_external_references'])('should still fail on a url that has no canonical JSON in %s', async (key) => {
    const references = [{ url: JSON.parse('"\\ud800"') }];
    await expect(createdReferences({ id: 'malware--refs', type: 'malware', [key]: references })).rejects.toThrow('Lone surrogate is not allowed');
  });
});

// pycti ExternalReference.generate_id, computed with client-python: the null test and the dedupe
// key on its canonical JSON, the id itself must stay pycti's
describe('externalReferenceId: pycti external_reference.generate_id', () => {
  it('should give the ids pycti gives', () => {
    expect(externalReferenceId('https://example.com/report', null, null)).toEqual('external-reference--4d4eeaf9-7eeb-5d7f-9c6a-80a9f6942712');
    expect(externalReferenceId(null, 'mitre-attack', 'T1059')).toEqual('external-reference--aecbe091-f97b-5cc7-8b42-ee9efb0c4a9f');
    expect(externalReferenceId(null, 'mitre-attack', null)).toBeNull();
  });
  it('should fail on a non-finite number as canonicalize does', () => {
    expect(() => externalReferenceId(null, 's', JSON.parse('1e999'))).toThrow('Infinity is not allowed');
  });
});
