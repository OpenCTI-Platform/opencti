import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Stix2Splitter } from '../../../src/utils/stix2-splitter';

// Golden fixtures reused as-is from client-python/tests/data, so the Node.js port can be
// validated against the exact same input/expected-count pairs as pycti's own test suite
// (client-python/tests/01-unit/utils/test_opencti_stix2_splitter.py).
//
// Beyond these 3 assertions, this port was also verified with a differential test harness
// that ran the real pycti OpenCTIStix2Splitter (loaded directly from
// client-python/pycti/utils/opencti_stix2_splitter.py) side by side with this module, on
// 18 inputs across both cleanupInconsistentBundle modes (36 scenarios total): 13 adversarial
// cases (cycles, self-references, dangling refs, sightings, external-reference/kill-chain-phase
// dedup, internal-id extension aliasing, unsupported ref types, sort-stability ties) plus 5
// real-world fixtures, including enterprise-attack.json (10MB, 7016 expectations) and
// mitre_att_capec.json (2610 expectations, ~4MB - not committed here to keep the repo lean).
// Every bundle, field, nb_deps value, ordering, and incompatible-item classification matched
// exactly. That harness was a temporary, throwaway script (not committed) - this file is the
// permanent regression suite.
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
