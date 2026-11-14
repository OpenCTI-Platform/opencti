import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import * as enterpriseEdition from '../../../src/enterprise-edition/ee';

const SCHEMA_ATTRIBUTES = gql`
  query SchemaAttributesTest($entityType: String) {
    schemaAttributes(entityType: $entityType) {
      type
      attributes { name label description mandatory }
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
const CUSTOM_FIELD_DELETE = gql`
  mutation SchemaAttributesCustomFieldDelete($id: ID!) {
    customFieldDefinitionDelete(id: $id)
  }
`;

type SchemaAttribute = { name: string; label: string; description: string | null; mandatory: boolean };
type AttributesMap = { type: string; attributes: SchemaAttribute[] };

const querySchemaAttributes = async (entityType?: string) => {
  const result = await queryAsAdmin({ query: SCHEMA_ATTRIBUTES, variables: { entityType } });
  expect(result.errors).toBeUndefined();
  return result.data?.schemaAttributes as AttributesMap[];
};

const RISK_LEVEL = 'x_opencti_cf_schema_risk_level';

describe('schemaAttributes', () => {
  let definitionId: string;

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
  });

  afterAll(async () => {
    await queryAsAdmin({ query: CUSTOM_FIELD_DELETE, variables: { id: definitionId } });
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

  it('should describe the custom fields and return null for an undescribed native attribute', async () => {
    const [malware] = await querySchemaAttributes(ENTITY_TYPE_MALWARE);
    const riskLevel = malware.attributes.find((attribute) => attribute.name === RISK_LEVEL);
    expect(riskLevel).toEqual({ name: RISK_LEVEL, label: 'Risk level', description: 'Risk level assessed by the analysts', mandatory: true });
    // The native attributes are described in a next step: until then, their description is null
    const name = malware.attributes.find((attribute) => attribute.name === 'name');
    expect(name?.description).toBeNull();
  });
});
