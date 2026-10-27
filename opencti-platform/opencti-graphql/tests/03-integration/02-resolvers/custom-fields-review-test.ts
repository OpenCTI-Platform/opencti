import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, queryAsUser } from '../../utils/testQueryHelper';
import { USER_EDITOR } from '../../utils/testQuery';
import { buildCustomFieldTaskInputs } from '../../../src/modules/customField/custom-field-task';
import type { BasicStoreEntityCustomFieldDefinition } from '../../../src/modules/customField/custom-field-types';
import type { EditInput } from '../../../src/generated/graphql';
import * as enterpriseEdition from '../../../src/enterprise-edition/ee';

const CUSTOM_FIELD_ADD = gql`
  mutation CustomFieldsReviewAdd($input: CustomFieldDefinitionAddInput!) {
    customFieldDefinitionAdd(input: $input) { id name }
  }
`;
const CUSTOM_FIELD_ADD_ENTITY_TYPE = gql`
  mutation CustomFieldsReviewAddEntityType($id: ID!, $entityType: String!, $mandatory: Boolean!) {
    customFieldDefinitionAddEntityType(id: $id, entityType: $entityType, mandatory: $mandatory) { id }
  }
`;
const CUSTOM_FIELD_DELETE = gql`
  mutation CustomFieldsReviewDelete($id: ID!) {
    customFieldDefinitionDelete(id: $id)
  }
`;
const MALWARE_ADD = gql`
  mutation CustomFieldsReviewMalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) { id }
  }
`;
const AREA_ADD = gql`
  mutation CustomFieldsReviewAreaAdd($input: AdministrativeAreaAddInput!) {
    administrativeAreaAdd(input: $input) { id }
  }
`;
const CASE_ADD = gql`
  mutation CustomFieldsReviewCaseAdd($input: CaseIncidentAddInput!) {
    caseIncidentAdd(input: $input) { id }
  }
`;
const CASE_READ = gql`
  query CustomFieldsReviewCaseRead($id: String!) {
    caseIncident(id: $id) {
      id
      customFieldValues { field_id field_name string_value int_value select_values }
    }
  }
`;
const CASES_FILTER = gql`
  query CustomFieldsReviewCasesFilter($filters: FilterGroup) {
    caseIncidents(first: 50, filters: $filters) { edges { node { id } } }
  }
`;
const SDO_FIELD_PATCH = gql`
  mutation CustomFieldsReviewSdoPatch($id: ID!, $input: [EditInput]!) {
    stixDomainObjectEdit(id: $id) { fieldPatch(input: $input) { id } }
  }
`;
const SDO_DELETE = gql`
  mutation CustomFieldsReviewSdoDelete($id: ID!) {
    stixDomainObjectEdit(id: $id) { delete }
  }
`;
const MERGE = gql`
  mutation CustomFieldsReviewMerge($id: ID!, $ids: [String]!) {
    stixEdit(id: $id) { merge(stixObjectsIds: $ids) { id } }
  }
`;
const RELATION_ADD = gql`
  mutation CustomFieldsReviewRelationAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) { id }
  }
`;
const RELATION_READ = gql`
  query CustomFieldsReviewRelationRead($id: String!) {
    stixCoreRelationship(id: $id) { id customFieldValues { field_id field_name string_value } }
  }
`;
const RELATION_FIELD_PATCH = gql`
  mutation CustomFieldsReviewRelationPatch($id: ID!, $input: [EditInput]!) {
    stixCoreRelationshipEdit(id: $id) { fieldPatch(input: $input) { id } }
  }
`;
const RELATION_DELETE = gql`
  mutation CustomFieldsReviewRelationDelete($id: ID!) {
    stixCoreRelationshipEdit(id: $id) { delete }
  }
`;
const SIGHTING_ADD = gql`
  mutation CustomFieldsReviewSightingAdd($input: StixSightingRelationshipAddInput!) {
    stixSightingRelationshipAdd(input: $input) { id }
  }
`;
const SIGHTING_READ = gql`
  query CustomFieldsReviewSightingRead($id: String!) {
    stixSightingRelationship(id: $id) { id customFieldValues { field_id field_name string_value } }
  }
`;
const SIGHTING_DELETE = gql`
  mutation CustomFieldsReviewSightingDelete($id: ID!) {
    stixSightingRelationshipEdit(id: $id) { delete }
  }
`;

const BACKGROUND_TASKS = gql`
  query CustomFieldsReviewBackgroundTasks {
    backgroundTasks(first: 100, orderBy: created_at, orderMode: desc) { edges { node { id actions { type context { values } } } } }
  }
`;

const NOTE = 'x_opencti_cf_review_note';
const TAGS = 'x_opencti_cf_review_tags';
const REQUIRED = 'x_opencti_cf_review_required';
const LEVEL = 'x_opencti_cf_review_level';
const DUE = 'x_opencti_cf_review_due';

const addDefinition = async (input: Record<string, unknown>, entityTypes: { entityType: string; mandatory: boolean }[]) => {
  const result = await queryAsAdmin({ query: CUSTOM_FIELD_ADD, variables: { input: { description: `${input.label} description`, ...input } } });
  expect(result.errors).toBeUndefined();
  const { id } = result.data?.customFieldDefinitionAdd ?? {};
  for (const { entityType, mandatory } of entityTypes) {
    const attachResult = await queryAsAdmin({ query: CUSTOM_FIELD_ADD_ENTITY_TYPE, variables: { id, entityType, mandatory } });
    expect(attachResult.errors).toBeUndefined();
  }
  return id as string;
};

const createCase = async (name: string, customFieldValues: { field_name: string; value: unknown[] }[]) => {
  const result = await queryAsAdmin({ query: CASE_ADD, variables: { input: { name, customFieldValues } } });
  expect(result.errors).toBeUndefined();
  return result.data?.caseIncidentAdd.id as string;
};

const readCaseValues = async (id: string) => {
  const result = await queryAsAdmin({ query: CASE_READ, variables: { id } });
  return result.data?.caseIncident.customFieldValues as Record<string, any>[];
};

// Managing the custom field definitions is an Enterprise Edition feature
beforeAll(() => {
  vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
});
afterAll(() => {
  vi.restoreAllMocks();
});

describe('Custom fields review: relationships, mandatory fields, filters and merge', () => {
  const definitionIds: string[] = [];
  const caseIds: string[] = [];
  let malwareId: string;
  let areaId: string;

  beforeAll(async () => {
    definitionIds.push(await addDefinition({ name: NOTE, label: 'Review note', field_type: 'string' }, [
      { entityType: 'Case-Incident', mandatory: false },
      { entityType: 'stix-core-relationship', mandatory: false },
      { entityType: 'stix-sighting-relationship', mandatory: false },
    ]));
    definitionIds.push(await addDefinition({ name: TAGS, label: 'Review tags', field_type: 'multi_select', select_options: ['a', 'b', 'c'] }, [
      { entityType: 'Case-Incident', mandatory: false },
    ]));
    definitionIds.push(await addDefinition({ name: LEVEL, label: 'Review level', field_type: 'integer' }, [
      { entityType: 'Case-Incident', mandatory: false },
    ]));
    definitionIds.push(await addDefinition({ name: DUE, label: 'Review due date', field_type: 'date' }, [
      { entityType: 'Case-Incident', mandatory: false },
    ]));
    const malware = await queryAsAdmin({ query: MALWARE_ADD, variables: { input: { name: 'Custom fields review malware' } } });
    malwareId = malware.data?.malwareAdd.id;
    const area = await queryAsAdmin({ query: AREA_ADD, variables: { input: { name: 'Custom fields review area' } } });
    areaId = area.data?.administrativeAreaAdd.id;
  });

  afterAll(async () => {
    for (const id of caseIds) {
      await queryAsAdmin({ query: SDO_DELETE, variables: { id } });
    }
    await queryAsAdmin({ query: SDO_DELETE, variables: { id: malwareId } });
    await queryAsAdmin({ query: SDO_DELETE, variables: { id: areaId } });
    for (const id of definitionIds) {
      await queryAsAdmin({ query: CUSTOM_FIELD_DELETE, variables: { id } });
    }
  });

  describe('relationships and sightings', () => {
    it('should store, read back and edit the custom field values of a relationship', async () => {
      const created = await queryAsAdmin({
        query: RELATION_ADD,
        variables: { input: { fromId: malwareId, toId: areaId, relationship_type: 'targets', customFieldValues: [{ field_name: NOTE, value: ['created'] }] } },
      });
      expect(created.errors).toBeUndefined();
      const relationId = created.data?.stixCoreRelationshipAdd.id;
      const read = await queryAsAdmin({ query: RELATION_READ, variables: { id: relationId } });
      const [value] = read.data?.stixCoreRelationship.customFieldValues ?? [];
      expect(value).toMatchObject({ field_name: NOTE, string_value: 'created' });

      const patched = await queryAsAdmin({
        query: RELATION_FIELD_PATCH,
        variables: { id: relationId, input: [{ key: 'custom_field_values', value: [{ ...value, string_value: 'edited' }] }] },
      });
      expect(patched.errors).toBeUndefined();
      const readAfterEdit = await queryAsAdmin({ query: RELATION_READ, variables: { id: relationId } });
      expect(readAfterEdit.data?.stixCoreRelationship.customFieldValues).toMatchObject([{ field_name: NOTE, string_value: 'edited' }]);
      await queryAsAdmin({ query: RELATION_DELETE, variables: { id: relationId } });
    });

    it('should store and read back the custom field values of a sighting', async () => {
      const created = await queryAsAdmin({
        query: SIGHTING_ADD,
        variables: { input: { fromId: malwareId, toId: areaId, attribute_count: 1, customFieldValues: [{ field_name: NOTE, value: ['sighted'] }] } },
      });
      expect(created.errors).toBeUndefined();
      const sightingId = created.data?.stixSightingRelationshipAdd.id;
      const read = await queryAsAdmin({ query: SIGHTING_READ, variables: { id: sightingId } });
      expect(read.data?.stixSightingRelationship.customFieldValues).toMatchObject([{ field_name: NOTE, string_value: 'sighted' }]);
      await queryAsAdmin({ query: SIGHTING_DELETE, variables: { id: sightingId } });
    });
  });

  describe('mandatory custom fields', () => {
    let requiredDefinitionId: string;
    let mandatoryCaseId: string;

    beforeAll(async () => {
      requiredDefinitionId = await addDefinition({ name: REQUIRED, label: 'Review required', field_type: 'string' }, [
        { entityType: 'Case-Incident', mandatory: true },
        { entityType: 'stix-core-relationship', mandatory: true },
      ]);
    });

    afterAll(async () => {
      // Delete the entity holding a value before the definition, so that the values cleanup task has nothing to update
      await queryAsAdmin({ query: SDO_DELETE, variables: { id: mandatoryCaseId } });
      await queryAsAdmin({ query: CUSTOM_FIELD_DELETE, variables: { id: requiredDefinitionId } });
    });

    it('should require a mandatory custom field of stix-core-relationship on a relationship type', async () => {
      const result = await queryAsUser(USER_EDITOR, {
        query: RELATION_ADD,
        variables: { input: { fromId: malwareId, toId: areaId, relationship_type: 'targets' } },
      });
      expect(result.errors?.[0].message).toEqual('Mandatory custom field is missing');
    });

    it('should not allow a user without bypass to remove a mandatory custom field value', async () => {
      mandatoryCaseId = await createCase('Custom fields review mandatory case', [{ field_name: REQUIRED, value: ['set'] }]);
      const result = await queryAsUser(USER_EDITOR, {
        query: SDO_FIELD_PATCH,
        variables: { id: mandatoryCaseId, input: [{ key: 'custom_field_values', value: [] }] },
      });
      expect(result.errors?.[0].message).toEqual('Mandatory custom field is missing');
    });
  });

  describe('filters', () => {
    let caseWithNoteId: string;
    let caseWithoutNoteId: string;
    let caseOtherId: string;

    const filterCases = async (key: string, operator: string, values: string[], mode = 'or') => {
      const filters = {
        mode: 'and',
        filterGroups: [],
        filters: [
          { key: ['ids'], values: [caseWithNoteId, caseWithoutNoteId, caseOtherId] },
          { key: [key], operator, values, mode },
        ],
      };
      const result = await queryAsAdmin({ query: CASES_FILTER, variables: { filters } });
      expect(result.errors).toBeUndefined();
      return (result.data?.caseIncidents.edges ?? []).map((edge: any) => edge.node.id).sort();
    };

    beforeAll(async () => {
      caseWithNoteId = await createCase('Custom fields review with note', [
        { field_name: NOTE, value: ['hello'] }, { field_name: TAGS, value: ['a', 'b'] }, { field_name: LEVEL, value: [10] },
        { field_name: DUE, value: ['2026-01-10T00:00:00.000Z'] },
      ]);
      caseWithoutNoteId = await createCase('Custom fields review without note', [
        { field_name: TAGS, value: ['a'] }, { field_name: LEVEL, value: [15] }, { field_name: DUE, value: ['2026-06-15T00:00:00.000Z'] },
      ]);
      caseOtherId = await createCase('Custom fields review other', [
        { field_name: TAGS, value: ['c'] }, { field_name: LEVEL, value: [20] }, { field_name: DUE, value: ['2026-12-20T00:00:00.000Z'] },
      ]);
      caseIds.push(caseWithNoteId, caseWithoutNoteId, caseOtherId);
    });

    it('should return the entities without the custom field with negative operators', async () => {
      const withoutNote = [caseWithoutNoteId, caseOtherId].sort();
      expect(await filterCases(NOTE, 'nil', [])).toEqual(withoutNote);
      expect(await filterCases(NOTE, 'not_nil', [])).toEqual([caseWithNoteId]);
      expect(await filterCases(NOTE, 'not_eq', ['hello'])).toEqual(withoutNote);
      expect(await filterCases(NOTE, 'not_contains', ['hel'])).toEqual(withoutNote);
    });

    it('should combine several values with the filter mode, as for a standard attribute', async () => {
      // a or b / a and b / not a or not b / neither a nor b
      expect(await filterCases(TAGS, 'eq', ['a', 'b'], 'or')).toEqual([caseWithNoteId, caseWithoutNoteId].sort());
      expect(await filterCases(TAGS, 'eq', ['a', 'b'], 'and')).toEqual([caseWithNoteId]);
      expect(await filterCases(TAGS, 'not_eq', ['a', 'b'], 'or')).toEqual([caseWithoutNoteId, caseOtherId].sort());
      expect(await filterCases(TAGS, 'not_eq', ['a', 'b'], 'and')).toEqual([caseOtherId]);
    });

    it('should match each integer value, not the interval between them', async () => {
      expect(await filterCases(LEVEL, 'eq', ['10', '20'], 'or')).toEqual([caseWithNoteId, caseOtherId].sort());
      expect(await filterCases(LEVEL, 'eq', ['10', '20'], 'and')).toEqual([]);
      expect(await filterCases(LEVEL, 'not_eq', ['10', '20'], 'or')).toEqual([caseWithNoteId, caseWithoutNoteId, caseOtherId].sort());
      expect(await filterCases(LEVEL, 'not_eq', ['10', '20'], 'and')).toEqual([caseWithoutNoteId]);
    });

    it('should match the range of within whatever the filter mode', async () => {
      const range = ['2026-05-01T00:00:00.000Z', '2026-07-01T00:00:00.000Z'];
      expect(await filterCases(DUE, 'within', range, 'or')).toEqual([caseWithoutNoteId]);
      expect(await filterCases(DUE, 'within', range, 'and')).toEqual([caseWithoutNoteId]);
    });

    it('should reject a custom field filter without value, as for a standard attribute', async () => {
      const filtersWithoutValue = (key: string) => ({ mode: 'and', filterGroups: [], filters: [{ key: [key], operator: 'not_eq', values: [], mode: 'or' }] });
      const standardAttribute = await queryAsAdmin({ query: CASES_FILTER, variables: { filters: filtersWithoutValue('description') } });
      const customField = await queryAsAdmin({ query: CASES_FILTER, variables: { filters: filtersWithoutValue(NOTE) } });
      expect(standardAttribute.errors?.[0].message).toEqual('Invalid filter configuration');
      expect(customField.errors?.[0].message).toEqual(standardAttribute.errors?.[0].message);
    });

    it('should filter on a deleted custom field as on a custom field no entity has', async () => {
      const deletedKey = 'x_opencti_cf_review_deleted';
      expect(await filterCases(deletedKey, 'eq', ['hello'])).toEqual([]);
      expect(await filterCases(deletedKey, 'nil', [])).toEqual([caseWithNoteId, caseWithoutNoteId, caseOtherId].sort());
    });
  });

  describe('merge', () => {
    it('should keep the target value and merge the multi_select options, with a single entry per custom field', async () => {
      const targetId = await createCase('Custom fields review merge target', [{ field_name: NOTE, value: ['target'] }, { field_name: TAGS, value: ['a'] }]);
      const sourceOneId = await createCase('Custom fields review merge source 1', [{ field_name: NOTE, value: ['source 1'] }, { field_name: TAGS, value: ['b'] }]);
      const sourceTwoId = await createCase('Custom fields review merge source 2', [{ field_name: NOTE, value: ['source 2'] }, { field_name: TAGS, value: ['c'] }]);
      caseIds.push(targetId);
      const merged = await queryAsAdmin({ query: MERGE, variables: { id: targetId, ids: [sourceOneId, sourceTwoId] } });
      expect(merged.errors).toBeUndefined();
      const values = await readCaseValues(targetId);
      expect(values.filter((v) => v.field_name === NOTE)).toMatchObject([{ string_value: 'target' }]);
      expect(values.filter((v) => v.field_name === TAGS)).toHaveLength(1);
      expect(values.find((v) => v.field_name === TAGS)?.select_values.sort()).toEqual(['a', 'b', 'c']);
    });
  });

  describe('remove', () => {
    it('should only remove the targeted custom field value', async () => {
      const caseId = await createCase('Custom fields review remove', [{ field_name: NOTE, value: ['note'] }, { field_name: TAGS, value: ['a'] }]);
      caseIds.push(caseId);
      const patched = await queryAsAdmin({
        query: SDO_FIELD_PATCH,
        variables: { id: caseId, input: [{ key: 'custom_field_values', value: [{ field_name: NOTE }], operation: 'remove' }] },
      });
      expect(patched.errors).toBeUndefined();
      const values = await readCaseValues(caseId);
      expect(values).toMatchObject([{ field_name: TAGS, select_values: ['a'] }]);
    });
  });

  describe('background task edits', () => {
    // The worker applies the inputs of a background task action in a single edit of each element
    const noteDefinition = { name: NOTE, field_type: 'string' } as BasicStoreEntityCustomFieldDefinition;
    const tagsDefinition = { name: TAGS, field_type: 'multi_select' } as BasicStoreEntityCustomFieldDefinition;
    const applyTask = async (id: string, input: EditInput[]) => {
      const patched = await queryAsAdmin({ query: SDO_FIELD_PATCH, variables: { id, input } });
      expect(patched.errors).toBeUndefined();
      return readCaseValues(id);
    };

    it('should replace, add and remove values and options on the current values', async () => {
      const caseId = await createCase('Custom fields review task', [{ field_name: NOTE, value: ['x'] }, { field_name: TAGS, value: ['a', 'b'] }]);
      caseIds.push(caseId);

      let values = await applyTask(caseId, [
        ...buildCustomFieldTaskInputs(tagsDefinition, 'REPLACE', ['c']),
        ...buildCustomFieldTaskInputs(noteDefinition, 'REPLACE', ['y']),
      ]);
      expect(values).toHaveLength(2);
      expect(values.find((v) => v.field_name === TAGS)?.select_values).toEqual(['c']);
      expect(values.find((v) => v.field_name === NOTE)?.string_value).toEqual('y');

      values = await applyTask(caseId, buildCustomFieldTaskInputs(tagsDefinition, 'ADD', ['a', 'b']));
      expect(values.find((v) => v.field_name === TAGS)?.select_values).toEqual(['c', 'a', 'b']);

      values = await applyTask(caseId, buildCustomFieldTaskInputs(tagsDefinition, 'REMOVE', ['a']));
      expect(values.find((v) => v.field_name === TAGS)?.select_values).toEqual(['c', 'b']);

      values = await applyTask(caseId, buildCustomFieldTaskInputs(noteDefinition, 'REMOVE', []));
      expect(values.map((v) => v.field_name)).toEqual([TAGS]);
    });
  });
});

describe('Custom fields review: deleted definition cleanup task', () => {
  it('should list the cleanup task of a deleted custom field definition', async () => {
    const definitionId = await addDefinition({ name: 'x_opencti_cf_review_deleted', label: 'Review deleted', field_type: 'string' }, [
      { entityType: 'Case-Incident', mandatory: false },
    ]);
    const deleted = await queryAsAdmin({ query: CUSTOM_FIELD_DELETE, variables: { id: definitionId } });
    expect(deleted.errors).toBeUndefined();
    const tasks = await queryAsAdmin({ query: BACKGROUND_TASKS, variables: {} });
    expect(tasks.errors).toBeUndefined();
    const actions = (tasks.data?.backgroundTasks.edges ?? []).flatMap(({ node }: any) => node.actions);
    expect(actions).toContainEqual({ type: 'REMOVE_CUSTOM_FIELD_VALUES', context: { values: [definitionId] } });
  });
});
