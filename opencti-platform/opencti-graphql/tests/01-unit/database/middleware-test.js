import { describe, expect, it } from 'vitest';
import { hashMergeValidation } from '../../../src/database/middleware';
import {generateAttributesInputsForUpsert} from "../../../src/utils/upsert-utils";
import {ADMIN_USER, testContext} from "../../utils/testQuery";
import {ENTITY_DOMAIN_NAME} from "../../../src/schema/stixCyberObservable";

describe('middleware hashMergeValidation test', () => {
  it('should hashes allowed to merge', () => {
    const instanceOne = { hashes: { MD5: 'md5', 'SHA-1': 'SHA' } };
    const instanceTwo = { hashes: { MD5: 'md5' } };
    hashMergeValidation([instanceOne, instanceTwo]);
  });

  it('should hashes have collisions', () => {
    const instanceOne = { hashes: { MD5: 'md5instanceOne' } };
    const instanceTwo = { hashes: { MD5: 'md5instanceTwo' } };
    const merge = () => hashMergeValidation([instanceOne, instanceTwo]);
    expect(merge).toThrow();
  });

  it('should hashes have complex collisions', () => {
    const instanceOne = { hashes: { MD5: 'md5', 'SHA-1': 'SHA' } };
    const instanceTwo = { hashes: { MD5: 'md5', 'SHA-1': 'SHA2' } };
    const merge = () => hashMergeValidation([instanceOne, instanceTwo]);
    expect(merge).toThrow();
  });
});

describe('middleware upsertElement test', () => {
  describe('middleware generateAttributesInputsForUpsert with indicator test', () => {
    const indicator1 = {
      id: 'indicator1-uuid-internal',
      internal_id: 'indicator1-uuid-internal',
      standard_id: 'indicator1-uuid-standard',
      pattern: '[domain-name:value = \'filigran.dev\']',
      pattern_type: 'stix',
      x_opencti_main_observable_type: ENTITY_DOMAIN_NAME,
    };
    const type = 'Indicator';
    const updatePatch = {
      standard_id: 'indicator1-uuid-standard',
      description: 'indicator1 new description',
    };
    it('should generateAttributesInputsForUpsert with indicator description update no old description', () => {
      const resolvedElement = { ...indicator1 };
      const type = 'Indicator';
      const updatePatch = {
        standard_id: 'indicator1-uuid-standard',
        description: 'indicator1 new description',
      };
      let confidenceForUpsert = { isConfidenceMatch: true }
      let inputs = generateAttributesInputsForUpsert(testContext, ADMIN_USER, resolvedElement, type, updatePatch, confidenceForUpsert);

      expect(inputs.length).toEqual(1);
      expect(inputs[0]).toEqual({key: 'description', value: ['indicator1 new description']})

      confidenceForUpsert = { isConfidenceMatch: false }
      inputs = generateAttributesInputsForUpsert(testContext, ADMIN_USER, resolvedElement, type, updatePatch, confidenceForUpsert);

      expect(inputs.length).toEqual(1); // we still update description since no existing
      expect(inputs[0]).toEqual({key: 'description', value: ['indicator1 new description']})
    });
    it('should generateAttributesInputsForUpsert with indicator description update', () => {
      const resolvedElement = { ...indicator1, description: 'indicator1 old description' }; // existing description

      let confidenceForUpsert = { isConfidenceMatch: true }
      let inputs = generateAttributesInputsForUpsert(testContext, ADMIN_USER, resolvedElement, type, updatePatch, confidenceForUpsert);

      expect(inputs.length).toEqual(1);
      expect(inputs[0]).toEqual({key: 'description', value: ['indicator1 new description']})

      confidenceForUpsert = { isConfidenceMatch: false }
      inputs = generateAttributesInputsForUpsert(testContext, ADMIN_USER, resolvedElement, type, updatePatch, confidenceForUpsert);

      expect(inputs.length).toEqual(0); // no changes since confidenceMatch is false, we don't replace existing description
    });
  });
});
