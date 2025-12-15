import { describe, expect, it } from 'vitest';
import { hashMergeValidation } from '../../../src/database/middleware';
import { generateAttributesInputsForUpsert, mergeUpsertInput, mergeUpsertInputs } from '../../../src/utils/upsert-utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { ENTITY_DOMAIN_NAME } from '../../../src/schema/stixCyberObservable';

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

      let confidenceForUpsert = { isConfidenceMatch: true };
      let inputs = generateAttributesInputsForUpsert(testContext, ADMIN_USER, resolvedElement, type, updatePatch, confidenceForUpsert);

      expect(inputs.length).toEqual(1);
      expect(inputs[0]).toEqual({ key: 'description', value: ['indicator1 new description'] });

      confidenceForUpsert = { isConfidenceMatch: false };
      inputs = generateAttributesInputsForUpsert(testContext, ADMIN_USER, resolvedElement, type, updatePatch, confidenceForUpsert);

      expect(inputs.length).toEqual(1); // we still update description since no existing
      expect(inputs[0]).toEqual({ key: 'description', value: ['indicator1 new description'] });
    });
    it('should generateAttributesInputsForUpsert with indicator description update', () => {
      const resolvedElement = { ...indicator1, description: 'indicator1 old description' }; // existing description

      let confidenceForUpsert = { isConfidenceMatch: true };
      let inputs = generateAttributesInputsForUpsert(testContext, ADMIN_USER, resolvedElement, type, updatePatch, confidenceForUpsert);

      expect(inputs.length).toEqual(1);
      expect(inputs[0]).toEqual({ key: 'description', value: ['indicator1 new description'] });

      confidenceForUpsert = { isConfidenceMatch: false };
      inputs = generateAttributesInputsForUpsert(testContext, ADMIN_USER, resolvedElement, type, updatePatch, confidenceForUpsert);

      expect(inputs.length).toEqual(0); // no changes since confidenceMatch is false, we don't replace existing description
    });

    it('should generateAttributesInputsForUpsert with indicator description update & indicator types unchanged', () => {
      const resolvedElement = { ...indicator1, description: 'indicator1 old description', indicator_types: ['type1', 'type2'] };
      const updatePatchWithTypes = { ...updatePatch, indicator_types: ['type1', 'type2'] };
      let confidenceForUpsert = { isConfidenceMatch: true };
      let inputs = generateAttributesInputsForUpsert(testContext, ADMIN_USER, resolvedElement, type, updatePatchWithTypes, confidenceForUpsert);

      expect(inputs.length).toEqual(2);
      expect(inputs[0]).toEqual({ key: 'description', value: ['indicator1 new description'] });
      expect(inputs[1]).toEqual({ key: 'indicator_types', value: ['type1', 'type2'], operation: 'add' });

      confidenceForUpsert = { isConfidenceMatch: false };
      inputs = generateAttributesInputsForUpsert(testContext, ADMIN_USER, resolvedElement, type, updatePatchWithTypes, confidenceForUpsert);

      expect(inputs.length).toEqual(0); // no changes since confidenceMatch is false, we don't replace existing description
    });
  });
  describe('middleware generateAttributesInputsForUpsert with opencti_upsert_operations test', () => {
    const indicator1 = {
      id: 'indicator1-uuid-internal',
      internal_id: 'indicator1-uuid-internal',
      standard_id: 'indicator1-uuid-standard',
      pattern: '[domain-name:value = \'filigran.dev\']',
      pattern_type: 'stix',
      x_opencti_main_observable_type: ENTITY_DOMAIN_NAME,
      indicator_types: ['ip', 'active-directory'],
    };
    const indicatorUpsertOperations = [
      {
        operation: 'remove',
        key: 'indicator_types',
        value: ['active-directory'],
      },
    ];
    const updatePatchIndicator1 = {
      standard_id: 'indicator1-uuid-standard',
      // indicator_types: ['malicious-activity'],
      indicatorUpsertOperations,
    };
    it('should mergeUpsertInputs with indicator : different keys', () => {
      const updatePatch = { ...updatePatchIndicator1, description: 'indicator new description' };
      const updatePatchInput = [{
        operation: 'replace',
        key: 'description',
        value: ['indicator new description'],
      }];
      const inputs = mergeUpsertInputs(indicator1, updatePatch, updatePatchInput, indicatorUpsertOperations);

      expect(inputs.length).toEqual(2);
      expect(inputs.find((n) => n.key === 'description')).toEqual({ operation: 'replace', key: 'description', value: ['indicator new description'] });
      expect(inputs.find((n) => n.key === 'indicator_types')).toEqual({ operation: 'remove', key: 'indicator_types', value: ['active-directory'] });
    });
    it('should mergeUpsertInputs with indicator : upsert adds type and operation removes another type', () => {
      const updatePatchInput = {
        operation: 'add',
        key: 'indicator_types',
        value: ['indicator-type-to-add'],
      };
      const upsertOperation = {
        operation: 'remove',
        key: 'indicator_types',
        value: ['indicator-type-to-remove'],
      };
      const elementCurrentValue = ['indicator-type-to-remove', 'indicator-type-current'];
      const upsertCurrentValue = ['indicator-type-current', 'indicator-type-to-add'];
      const input = mergeUpsertInput(elementCurrentValue, upsertCurrentValue, updatePatchInput, upsertOperation);

      // inputs should be operation: 'replace', value: ['indicator-type-current', 'indicator-type-to-add']
      expect(input.key).toEqual('indicator_types');
      expect(input.operation).toEqual('replace');
      expect(input.value.length).toEqual(2);
      expect(input.value.includes('indicator-type-current')).toBe(true);
      expect(input.value.includes('indicator-type-to-add')).toBe(true);
    });

    it('should mergeUpsertInputs with indicator : upsert adds back the same type that was removed, not in DB', () => {
      const updatePatchInput = {
        operation: 'add',
        key: 'indicator_types',
        value: ['indicator-type-1'],
      };
      // remove operation done before, bundle contains again the type, we should keep it
      const upsertOperation = {
        operation: 'remove',
        key: 'indicator_types',
        value: ['indicator-type-1'],
      };
      const elementCurrentValue = ['indicator-type-current'];
      const upsertCurrentValue = ['indicator-type-1', 'indicator-type-current'];
      const input = mergeUpsertInput(elementCurrentValue, upsertCurrentValue, updatePatchInput, upsertOperation);

      // input should be operation: 'replace', value: ['indicator-type-1', 'indicator-type-current']
      expect(input.key).toEqual('indicator_types');
      expect(input.operation).toEqual('replace');
      expect(input.value.length).toEqual(2);
      expect(input.value.includes('indicator-type-current')).toBe(true);
      expect(input.value.includes('indicator-type-1')).toBe(true);
    });

    // skip this one for now, not implemented yet
    it.skip('should mergeUpsertInputs with indicator : upsert adds back the same type that was removed, already in DB', () => {
      const updatePatchInput = {
        operation: 'add',
        key: 'indicator_types',
        value: ['indicator-type-1'],
      };
      // remove operation done before, bundle contains again the type, we should keep it
      const upsertOperation = {
        operation: 'remove',
        key: 'indicator_types',
        value: ['indicator-type-1'],
      };
      const elementCurrentValue = ['indicator-type-1', 'indicator-type-current'];
      const upsertCurrentValue = ['indicator-type-1', 'indicator-type-current'];
      const inputs = mergeUpsertInput(elementCurrentValue, upsertCurrentValue, updatePatchInput, upsertOperation);

      // TODO inputs should be empty
      console.log('inputs', inputs);
    });
    const labelToRemove = {
      _id: '0fc83074-eb2d-47f6-b315-781e511f0322',
      _index: 'opencti_stix_meta_objects-000001',
      base_type: 'ENTITY',
      color: '#320dff',
      confidence: 100,
      created: '2025-07-02T15:23:00.703Z',
      created_at: '2025-07-02T15:23:00.703Z',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      ],
      entity_type: 'Label',
      id: '0fc83074-eb2d-47f6-b315-781e511f0322',
      internal_id: '0fc83074-eb2d-47f6-b315-781e511f0322',
      modified: '2025-07-02T15:23:00.703Z',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object',
      ],
      standard_id: 'label--00785e04-8bf4-52ee-bba2-88ccecc17b8d',
      updated_at: '2025-07-02T15:23:00.703Z',
      value: 'label-to-remove',
    };
    it('should mergeUpsertInputs with indicator with only upsertOperation with remove label', () => {
      const updatePatch = { ...updatePatchIndicator1, description: 'indicator new description' };
      const upsertOperations = [{
        operation: 'remove',
        key: 'objectLabel',
        value: [labelToRemove],
      }];
      const updatePatchInput = [{
        operation: 'replace',
        key: 'description',
        value: ['indicator new description'],
      }];
      const inputs = mergeUpsertInputs(indicator1, updatePatch, updatePatchInput, upsertOperations);

      expect(inputs.length).toEqual(2);
      expect(inputs.find((n) => n.key === 'description')).toEqual({ operation: 'replace', key: 'description', value: ['indicator new description'] });
      expect(inputs.find((n) => n.key === 'objectLabel')).toEqual({ operation: 'remove', key: 'objectLabel', value: [labelToRemove] });
    });
    it('should mergeUpsertInputs with indicator : upsert adds label and operation removes another label', () => {
      const labelToAddId = 'eda3b7d5-b722-4c34-9dd5-d70cea8f5cfc';
      const labelToAdd = { ...labelToRemove, value: 'label-to-add', id: labelToAddId, internal_id: labelToAddId, standard_id: labelToAddId };
      const labelCurrentId = 'ada3b7d5-b722-4c34-9dd5-d70cea8f5cfc';
      const labelCurrentValue = { ...labelToRemove, value: 'label-current', id: labelCurrentId, internal_id: labelCurrentId, standard_id: labelCurrentId };
      const updatePatchInput = {
        operation: 'add',
        key: 'objectLabel',
        value: [labelToAdd],
      };
      const upsertOperation = {
        operation: 'remove',
        key: 'objectLabel',
        value: [labelToRemove],
      };
      const elementCurrentValue = [labelToRemove, labelCurrentValue];
      const upsertCurrentValue = [labelCurrentValue, labelToAdd];
      const input = mergeUpsertInput(elementCurrentValue, upsertCurrentValue, updatePatchInput, upsertOperation);

      // inputs should be operation: 'replace', value: [labelCurrentValue, labelToAdd]
      expect(input.key).toEqual('objectLabel');
      expect(input.operation).toEqual('replace');
      expect(input.value.length).toEqual(2);
      expect(input.value.some((v) => v.value === labelCurrentValue.value)).toBe(true);
      expect(input.value.some((v) => v.value === labelToAdd.value)).toBe(true);
    });
  });
});
