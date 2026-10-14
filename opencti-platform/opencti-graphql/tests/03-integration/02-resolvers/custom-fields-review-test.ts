import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, queryAsUser } from '../../utils/testQueryHelper';
import { USER_EDITOR } from '../../utils/testQuery';

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

const NOTE = 'x_opencti_cf_review_note';
const TAGS = 'x_opencti_cf_review_tags';
const REQUIRED = 'x_opencti_cf_review_required';

const addDefinition = async (input: Record<string, unknown>, entityTypes: { entityType: string; mandatory: boolean }[]) => {
  const result = await queryAsAdmin({ query: CUSTOM_FIELD_ADD, variables: { input } });
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

    beforeAll(async () => {
      requiredDefinitionId = await addDefinition({ name: REQUIRED, label: 'Review required', field_type: 'string' }, [
        { entityType: 'Case-Incident', mandatory: true },
        { entityType: 'stix-core-relationship', mandatory: true },
      ]);
    });

    afterAll(async () => {
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
      const caseId = await createCase('Custom fields review mandatory case', [{ field_name: REQUIRED, value: ['set'] }]);
      caseIds.push(caseId);
      const result = await queryAsUser(USER_EDITOR, {
        query: SDO_FIELD_PATCH,
        variables: { id: caseId, input: [{ key: 'custom_field_values', value: [] }] },
      });
      expect(result.errors?.[0].message).toEqual('Mandatory custom field is missing');
    });
  });

  describe('filters', () => {
    let caseWithNoteId: string;
    let caseWithoutNoteId: string;

    const filterCases = async (key: string, operator: string, values: string[]) => {
      const filters = {
        mode: 'and',
        filterGroups: [],
        filters: [
          { key: ['ids'], values: [caseWithNoteId, caseWithoutNoteId] },
          { key: [key], operator, values, mode: 'or' },
        ],
      };
      const result = await queryAsAdmin({ query: CASES_FILTER, variables: { filters } });
      expect(result.errors).toBeUndefined();
      return (result.data?.caseIncidents.edges ?? []).map((edge: any) => edge.node.id).sort();
    };

    beforeAll(async () => {
      caseWithNoteId = await createCase('Custom fields review with note', [{ field_name: NOTE, value: ['hello'] }]);
      caseWithoutNoteId = await createCase('Custom fields review without note', []);
      caseIds.push(caseWithNoteId, caseWithoutNoteId);
    });

    it('should return the entities without the custom field with negative operators', async () => {
      expect(await filterCases(NOTE, 'nil', [])).toEqual([caseWithoutNoteId]);
      expect(await filterCases(NOTE, 'not_nil', [])).toEqual([caseWithNoteId]);
      expect(await filterCases(NOTE, 'not_eq', ['hello'])).toEqual([caseWithoutNoteId]);
      expect(await filterCases(NOTE, 'not_contains', ['hel'])).toEqual([caseWithoutNoteId]);
    });

    it('should filter on a deleted custom field as on a custom field no entity has', async () => {
      const deletedKey = 'x_opencti_cf_review_deleted';
      expect(await filterCases(deletedKey, 'eq', ['hello'])).toEqual([]);
      expect(await filterCases(deletedKey, 'nil', [])).toEqual([caseWithNoteId, caseWithoutNoteId].sort());
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
});
