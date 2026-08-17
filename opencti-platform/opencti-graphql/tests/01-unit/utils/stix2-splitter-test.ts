import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Stix2Splitter } from '../../../src/utils/stix2-splitter';

// Golden fixtures reused as-is from client-python/tests/data, so the Node.js port can be
// validated against the exact same input/expected-count pairs as pycti's own test suite
// (client-python/tests/01-unit/utils/test_opencti_stix2_splitter.py): the base test bundle,
// mono-object entity/relationship cases, and the adversarial cycles/dangling-refs/internal-id
// fixtures below. The larger real-world fixtures from pycti's suite (enterprise-attack.json,
// mitre_att_capec.json, several MB each) were also run once against this port during
// development with matching results, but are intentionally not committed here to keep the
// repo lean - the fixtures below are the permanent, committed regression suite.
const fixturePath = (name: string) => join(__dirname, '../../data/stix2-splitter', name);

describe('Stix2Splitter: split_bundle_with_expectations parity with pycti', () => {
  it('should split the DATA-TEST-STIX2_v2 bundle preserving every object unchanged', () => {
    const splitter = new Stix2Splitter();
    const content = readFileSync(fixturePath('DATA-TEST-STIX2_v2.json'), 'utf-8');
    const { numberExpectations, bundles } = splitter.splitBundleWithExpectations(content);

    expect(numberExpectations).toEqual(59);

    const baseObjects = JSON.parse(content).objects;
    for (const base of baseObjects) {
      let found;
      for (const bundle of bundles as string[]) {
        const jsonBundle = JSON.parse(bundle);
        const objectJson = jsonBundle.objects[0];
        if (objectJson.id === base.id) {
          found = objectJson;
          break;
        }
      }
      expect(found, `Every object of the bundle must be available: ${base.id}`).toBeDefined();
      const { nb_deps: _nbDeps, ...foundWithoutDeps } = found;
      expect(foundWithoutDeps).toEqual(base);
    }
  });

  it('should split a mono-entity bundle and keep created_by_ref unless cleanup is requested', () => {
    const content = readFileSync(fixturePath('mono-bundle-entity.json'), 'utf-8');

    const splitter = new Stix2Splitter();
    const { numberExpectations, bundles } = splitter.splitBundleWithExpectations(content);
    expect(numberExpectations).toEqual(1);
    const jsonBundle = JSON.parse((bundles as string[])[0]).objects[0];
    expect(jsonBundle.created_by_ref).toEqual('fa42a846-8d90-4e51-bc29-71d5b4802168');

    const cleanupSplitter = new Stix2Splitter();
    const cleanupResult = cleanupSplitter.splitBundleWithExpectations(content, true, undefined, true);
    expect(cleanupResult.numberExpectations).toEqual(1);
    const cleanupJsonBundle = JSON.parse((cleanupResult.bundles as string[])[0]).objects[0];
    expect(cleanupJsonBundle.created_by_ref).toBeNull();
  });

  it('should split a mono-relationship bundle and mark it incompatible when endpoints are cleaned', () => {
    const content = readFileSync(fixturePath('mono-bundle-relationship.json'), 'utf-8');

    const splitter = new Stix2Splitter();
    const { numberExpectations } = splitter.splitBundleWithExpectations(content);
    expect(numberExpectations).toEqual(1);

    const cleanupSplitter = new Stix2Splitter();
    const cleanupResult = cleanupSplitter.splitBundleWithExpectations(content, true, undefined, true);
    expect(cleanupResult.numberExpectations).toEqual(0);
  });

  // Adversarial fixtures reused as-is from pycti's own splitter test suite
  // (client-python/tests/data, client-python/tests/01-unit/utils/test_opencti_stix2_splitter.py),
  // so cycles/self-references/dangling-refs/internal-id-aliasing coverage is checked against the
  // same expected values pycti's own CI already verifies, not values derived independently here.
  it('should resolve cyclic references, dedupe external references and markings, and count 6 expectations', () => {
    const content = readFileSync(fixturePath('cyclic-bundle.json'), 'utf-8');
    const splitter = new Stix2Splitter();
    const { numberExpectations, bundles } = splitter.splitBundleWithExpectations(content);

    expect(numberExpectations).toEqual(6);
    const reportBundle = (bundles as string[])
      .map((bundle) => JSON.parse(bundle).objects[0])
      .find((object) => object.id === 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    expect(reportBundle.external_references).toHaveLength(1);
    expect(reportBundle.object_refs).toHaveLength(2);
    expect(reportBundle.object_marking_refs).toEqual(['marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27']);
  });

  it('should keep 4 expectations for missing refs, dropping to 3 once inconsistent refs are cleaned up', () => {
    const content = readFileSync(fixturePath('missing_refs.json'), 'utf-8');

    const splitter = new Stix2Splitter();
    expect(splitter.splitBundleWithExpectations(content).numberExpectations).toEqual(4);

    const cleanupSplitter = new Stix2Splitter();
    expect(cleanupSplitter.splitBundleWithExpectations(content, true, undefined, true).numberExpectations).toEqual(3);
  });

  it('should resolve internal-id extension aliasing and count 4 expectations regardless of cleanup mode', () => {
    const content = readFileSync(fixturePath('bundle_with_internal_ids.json'), 'utf-8');

    const splitter = new Stix2Splitter();
    const { numberExpectations, bundles } = splitter.splitBundleWithExpectations(content);
    expect(numberExpectations).toEqual(4);

    const cleanupSplitter = new Stix2Splitter();
    const cleanupResult = cleanupSplitter.splitBundleWithExpectations(content, true, undefined, true);
    expect(cleanupResult.numberExpectations).toEqual(4);

    const relationshipBundle = (bundles as string[])
      .map((bundle) => JSON.parse(bundle).objects[0])
      .find((object) => object.id === 'relationship--10e8c71d-a1b4-4e35-bca8-2e4a3785ea04');
    expect(relationshipBundle.created_by_ref).toEqual('ced3e53e-9663-4c96-9c60-07d2e778d931');
  });

  it('should produce identical, uncontaminated results when the same instance is reused across two different bundles', () => {
    const first = JSON.stringify({ id: 'bundle--first', type: 'bundle', objects: [{ id: 'malware--a', type: 'malware' }, { id: 'malware--b', type: 'malware' }] });
    const second = JSON.stringify({ id: 'bundle--second', type: 'bundle', objects: [{ id: 'malware--c', type: 'malware' }] });

    const reusedSplitter = new Stix2Splitter();
    const firstResult = reusedSplitter.splitBundleWithExpectations(first);
    const secondResult = reusedSplitter.splitBundleWithExpectations(second);

    const freshSecondResult = new Stix2Splitter().splitBundleWithExpectations(second);
    expect(secondResult.numberExpectations).toEqual(freshSecondResult.numberExpectations);
    expect(secondResult.bundles).toEqual(freshSecondResult.bundles);
    // The second call's output must not carry over any state (cached elements/refs) from the first.
    expect(firstResult.numberExpectations).toEqual(2);
    expect(secondResult.numberExpectations).toEqual(1);
  });
});
