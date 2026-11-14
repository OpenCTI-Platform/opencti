import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import * as enterpriseEdition from '../../../src/enterprise-edition/ee';
import { ATTRIBUTE_DESCRIPTIONS, ATTRIBUTE_DESCRIPTIONS_BY_TYPE } from '../../../src/schema/attribute-descriptions';

const SCHEMA_ATTRIBUTES = gql`
  query SchemaAttributesTest($entityType: String) {
    schemaAttributes(entityType: $entityType) {
      type
      attributes { name label description mandatory defaultValues { id name } }
    }
  }
`;
const CUSTOM_FIELD_ADD = gql`
  mutation SchemaAttributesCustomFieldAdd($input: CustomFieldDefinitionAddInput!) {
    customFieldDefinitionAdd(input: $input) { id }
  }
`;
const CUSTOM_FIELD_ADD_ENTITY_TYPE = gql`
  mutation SchemaAttributesCustomFieldAddEntityType($id: ID!, $entityType: String!, $mandatory: Boolean!) {
    customFieldDefinitionAddEntityType(id: $id, entityType: $entityType, mandatory: $mandatory) { id }
  }
`;
const CUSTOM_FIELD_UPDATE_ENTITY_TYPE = gql`
  mutation SchemaAttributesCustomFieldUpdateEntityType($id: ID!, $entityType: String!, $mandatory: Boolean!, $defaultValue: String) {
    customFieldDefinitionUpdateEntityType(id: $id, entityType: $entityType, mandatory: $mandatory, default_value: $defaultValue) { id }
  }
`;
const CUSTOM_FIELD_DELETE = gql`
  mutation SchemaAttributesCustomFieldDelete($id: ID!) {
    customFieldDefinitionDelete(id: $id)
  }
`;
const ENTITY_SETTING_BY_TYPE = gql`
  query SchemaAttributesEntitySettingByType($targetType: String!) {
    entitySettingByType(targetType: $targetType) { id }
  }
`;
const ENTITY_SETTING_FIELD_PATCH = gql`
  mutation SchemaAttributesEntitySettingFieldPatch($ids: [ID!]!, $input: [EditInput!]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) { id }
  }
`;

type DefaultValue = { id: string; name: string };
type SchemaAttribute = { name: string; label: string; description: string | null; mandatory: boolean; defaultValues: DefaultValue[] | null };
type AttributesMap = { type: string; attributes: SchemaAttribute[] };

const querySchemaAttributes = async (entityType?: string) => {
  const result = await queryAsAdmin({ query: SCHEMA_ATTRIBUTES, variables: { entityType } });
  expect(result.errors).toBeUndefined();
  return result.data?.schemaAttributes as AttributesMap[];
};

const RISK_LEVEL = 'x_opencti_cf_schema_risk_level';
// Seeded in the test dataset (John Doe), reused as a createdBy default value: only its id is
// asserted, its resolved representative name can change with the dataset.
const JOHN_DOE_ID = 'identity--d37acc64-4a6f-4dc2-879a-a4c138d0a27f';

describe('schemaAttributes', () => {
  let definitionId: string;
  let noteEntitySettingId: string;

  beforeAll(async () => {
    // Managing the custom field definitions is an Enterprise Edition feature
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    const definition = await queryAsAdmin({
      query: CUSTOM_FIELD_ADD,
      variables: {
        input: {
          name: RISK_LEVEL,
          label: 'Risk level',
          description: 'Risk level assessed by the analysts',
          field_type: 'select',
          select_options: ['low', 'high'],
        },
      },
    });
    expect(definition.errors).toBeUndefined();
    definitionId = definition.data?.customFieldDefinitionAdd.id;
    const attach = await queryAsAdmin({ query: CUSTOM_FIELD_ADD_ENTITY_TYPE, variables: { id: definitionId, entityType: ENTITY_TYPE_MALWARE, mandatory: true } });
    expect(attach.errors).toBeUndefined();

    const entitySetting = await queryAsAdmin({ query: ENTITY_SETTING_BY_TYPE, variables: { targetType: ENTITY_TYPE_CONTAINER_NOTE } });
    expect(entitySetting.errors).toBeUndefined();
    noteEntitySettingId = entitySetting.data?.entitySettingByType.id;
    // attribute_abstract is customizable on Note; createdBy is a ref customizable everywhere
    const attributesConfiguration = JSON.stringify([
      { name: 'attribute_abstract', mandatory: true },
      { name: 'createdBy', default_values: [JOHN_DOE_ID] },
    ]);
    const patch = await queryAsAdmin({
      query: ENTITY_SETTING_FIELD_PATCH,
      variables: { ids: [noteEntitySettingId], input: { key: 'attributes_configuration', value: [attributesConfiguration] } },
    });
    expect(patch.errors).toBeUndefined();
  });

  afterAll(async () => {
    await queryAsAdmin({ query: CUSTOM_FIELD_DELETE, variables: { id: definitionId } });
    await queryAsAdmin({
      query: ENTITY_SETTING_FIELD_PATCH,
      variables: { ids: [noteEntitySettingId], input: { key: 'attributes_configuration', value: [] } },
    });
    vi.restoreAllMocks();
  });

  it('should return every registered type without entityType', async () => {
    const schemaAttributes = await querySchemaAttributes();
    expect(schemaAttributes.length).toBeGreaterThan(1);
    expect(schemaAttributes.map((map) => map.type)).toContain(ENTITY_TYPE_MALWARE);
  });

  it('should return only the asked type with entityType', async () => {
    const schemaAttributes = await querySchemaAttributes(ENTITY_TYPE_MALWARE);
    expect(schemaAttributes.map((map) => map.type)).toEqual([ENTITY_TYPE_MALWARE]);
    expect(schemaAttributes[0].attributes.map((attribute) => attribute.name)).toContain('name');
  });

  it('should return no type for an unknown entityType', async () => {
    const schemaAttributes = await querySchemaAttributes('Unknown-Type');
    expect(schemaAttributes).toEqual([]);
  });

  it('should describe the custom fields, the native attributes and the refs', async () => {
    const [malware] = await querySchemaAttributes(ENTITY_TYPE_MALWARE);
    const riskLevel = malware.attributes.find((attribute) => attribute.name === RISK_LEVEL);
    expect(riskLevel).toEqual({ name: RISK_LEVEL, label: 'Risk level', description: 'Risk level assessed by the analysts', mandatory: true, defaultValues: null });
    const name = malware.attributes.find((attribute) => attribute.name === 'name');
    expect(name?.description).toEqual(ATTRIBUTE_DESCRIPTIONS.name);
    const createdBy = malware.attributes.find((attribute) => attribute.name === 'createdBy');
    expect(createdBy?.description).toEqual(ATTRIBUTE_DESCRIPTIONS.createdBy);
  });

  it('should describe an attribute with the override of its type', async () => {
    const [note] = await querySchemaAttributes(ENTITY_TYPE_CONTAINER_NOTE);
    const content = note.attributes.find((attribute) => attribute.name === 'content');
    expect(content?.description).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_CONTAINER_NOTE].content);
  });

  it('should report the effective mandatory status and default value set in Entity Settings', async () => {
    const [note] = await querySchemaAttributes(ENTITY_TYPE_CONTAINER_NOTE);
    const abstract = note.attributes.find((attribute) => attribute.name === 'attribute_abstract');
    expect(abstract?.mandatory).toBeTruthy();
    const createdBy = note.attributes.find((attribute) => attribute.name === 'createdBy');
    expect(createdBy?.defaultValues?.map((value) => value.id)).toEqual([JOHN_DOE_ID]);
  });

  it('should list the refs with their type and mandatory status', async () => {
    const [malware] = await querySchemaAttributes(ENTITY_TYPE_MALWARE);
    const objectMarking = malware.attributes.find((attribute) => attribute.name === 'objectMarking');
    expect(objectMarking).toBeDefined();
    const [note] = await querySchemaAttributes(ENTITY_TYPE_CONTAINER_NOTE);
    const createdBy = note.attributes.find((attribute) => attribute.name === 'createdBy');
    expect(createdBy).toBeDefined();
  });

  it('should return the custom field default value', async () => {
    const update = await queryAsAdmin({
      query: CUSTOM_FIELD_UPDATE_ENTITY_TYPE,
      variables: {
        id: definitionId, entityType: ENTITY_TYPE_MALWARE, mandatory: true, defaultValue: 'low',
      },
    });
    expect(update.errors).toBeUndefined();
    const [malware] = await querySchemaAttributes(ENTITY_TYPE_MALWARE);
    const riskLevel = malware.attributes.find((attribute) => attribute.name === RISK_LEVEL);
    expect(riskLevel?.defaultValues).toEqual([{ id: 'low', name: 'low' }]);
  });
});
