import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, queryAsAuthUser } from '../../utils/testQueryHelper';
import { getAuthUser, USER_EDITOR } from '../../utils/testQuery';
import type { AuthUser } from '../../../src/types/user';
import { SETTINGS_SETCUSTOMFIELDS, SETTINGS_SETCUSTOMIZATION } from '../../../src/utils/access';
import * as enterpriseEdition from '../../../src/enterprise-edition/ee';

const CUSTOM_FIELD_ADD = gql`
  mutation CustomFieldCapabilitiesAdd($input: CustomFieldDefinitionAddInput!) {
    customFieldDefinitionAdd(input: $input) { id name }
  }
`;
const CUSTOM_FIELD_PATCH = gql`
  mutation CustomFieldCapabilitiesPatch($id: ID!, $input: [EditInput!]!) {
    customFieldDefinitionFieldPatch(id: $id, input: $input) { id description entity_types }
  }
`;
const CUSTOM_FIELD_ADD_ENTITY_TYPE = gql`
  mutation CustomFieldCapabilitiesAddEntityType($id: ID!, $entityType: String!, $mandatory: Boolean!) {
    customFieldDefinitionAddEntityType(id: $id, entityType: $entityType, mandatory: $mandatory) { id entity_types }
  }
`;
const CUSTOM_FIELD_REMOVE_ENTITY_TYPE = gql`
  mutation CustomFieldCapabilitiesRemoveEntityType($id: ID!, $entityType: String!) {
    customFieldDefinitionRemoveEntityType(id: $id, entityType: $entityType) { id entity_types }
  }
`;
const CUSTOM_FIELD_DELETE = gql`
  mutation CustomFieldCapabilitiesDelete($id: ID!) {
    customFieldDefinitionDelete(id: $id)
  }
`;
const CUSTOM_FIELD_READ = gql`
  query CustomFieldCapabilitiesRead($id: String!) {
    customFieldDefinition(id: $id) { id name }
  }
`;
const CUSTOM_FIELD_LIST = gql`
  query CustomFieldCapabilitiesList {
    customFieldDefinitions(first: 500) { edges { node { id name } } }
  }
`;

// A non admin test user holding a single settings capability, without knowledge access
// (the admin id is granted every capability by the auth directive)
const userWith = async (capability: string): Promise<AuthUser> => {
  const user = await getAuthUser(USER_EDITOR.id);
  return { ...user, capabilities: [{ name: 'SETTINGS' }, { name: capability }], capabilitiesInDraft: [] };
};
let CUSTOM_FIELDS_MANAGER: AuthUser;
let CUSTOMIZATION_MANAGER: AuthUser;

const definitionInput = (suffix: string) => ({
  name: `x_opencti_cf_capabilities_${suffix}`,
  label: `Capabilities ${suffix}`,
  field_type: 'string',
  description: 'Custom field of the capabilities test',
});
const expectForbidden = (result: { errors?: readonly { extensions?: Record<string, unknown> }[] }) => {
  expect(result.errors?.[0]?.extensions?.code).toEqual('FORBIDDEN_ACCESS');
};

beforeAll(async () => {
  vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
  CUSTOM_FIELDS_MANAGER = await userWith(SETTINGS_SETCUSTOMFIELDS);
  CUSTOMIZATION_MANAGER = await userWith(SETTINGS_SETCUSTOMIZATION);
});
afterAll(() => {
  vi.restoreAllMocks();
});

describe('Custom field capabilities', () => {
  let definitionId: string;

  afterAll(async () => {
    if (definitionId) {
      await queryAsAdmin({ query: CUSTOM_FIELD_DELETE, variables: { id: definitionId } });
    }
  });

  it('should let Manage custom fields create a custom field, but not Manage customization', async () => {
    const denied = await queryAsAuthUser(CUSTOMIZATION_MANAGER, { query: CUSTOM_FIELD_ADD, variables: { input: definitionInput('denied') } });
    expectForbidden(denied);
    const created = await queryAsAuthUser(CUSTOM_FIELDS_MANAGER, { query: CUSTOM_FIELD_ADD, variables: { input: definitionInput('managed') } });
    expect(created.errors).toBeUndefined();
    definitionId = created.data?.customFieldDefinitionAdd.id;
    expect(definitionId).toBeDefined();
  });

  it('should let both capabilities read the custom fields without knowledge access', async () => {
    for (const user of [CUSTOM_FIELDS_MANAGER, CUSTOMIZATION_MANAGER]) {
      const read = await queryAsAuthUser(user, { query: CUSTOM_FIELD_READ, variables: { id: definitionId } });
      expect(read.errors).toBeUndefined();
      expect(read.data?.customFieldDefinition.id).toEqual(definitionId);
      const list = await queryAsAuthUser(user, { query: CUSTOM_FIELD_LIST, variables: {} });
      expect(list.errors).toBeUndefined();
      expect(list.data?.customFieldDefinitions.edges.map(({ node }: { node: { id: string } }) => node.id)).toContain(definitionId);
    }
  });

  it('should let Manage custom fields edit the definition, but not Manage customization', async () => {
    const input = [{ key: 'description', value: ['Edited description'] }];
    expectForbidden(await queryAsAuthUser(CUSTOMIZATION_MANAGER, { query: CUSTOM_FIELD_PATCH, variables: { id: definitionId, input } }));
    const edited = await queryAsAuthUser(CUSTOM_FIELDS_MANAGER, { query: CUSTOM_FIELD_PATCH, variables: { id: definitionId, input } });
    expect(edited.errors).toBeUndefined();
    expect(edited.data?.customFieldDefinitionFieldPatch.description).toEqual('Edited description');
  });

  it('should let Manage customization attach and detach the custom field, but not Manage custom fields', async () => {
    const variables = { id: definitionId, entityType: 'Report', mandatory: false };
    expectForbidden(await queryAsAuthUser(CUSTOM_FIELDS_MANAGER, { query: CUSTOM_FIELD_ADD_ENTITY_TYPE, variables }));
    const attached = await queryAsAuthUser(CUSTOMIZATION_MANAGER, { query: CUSTOM_FIELD_ADD_ENTITY_TYPE, variables });
    expect(attached.errors).toBeUndefined();
    expect(attached.data?.customFieldDefinitionAddEntityType.entity_types).toEqual(['Report']);
    const detachVariables = { id: definitionId, entityType: 'Report' };
    expectForbidden(await queryAsAuthUser(CUSTOM_FIELDS_MANAGER, { query: CUSTOM_FIELD_REMOVE_ENTITY_TYPE, variables: detachVariables }));
    const detached = await queryAsAuthUser(CUSTOMIZATION_MANAGER, { query: CUSTOM_FIELD_REMOVE_ENTITY_TYPE, variables: detachVariables });
    expect(detached.errors).toBeUndefined();
    expect(detached.data?.customFieldDefinitionRemoveEntityType.entity_types).toEqual([]);
  });

  it('should not let Manage custom fields attach the custom field through the creation or the edition', async () => {
    const created = await queryAsAuthUser(CUSTOM_FIELDS_MANAGER, {
      query: CUSTOM_FIELD_ADD,
      variables: { input: { ...definitionInput('attached'), entity_types: ['Report'] } },
    });
    expect(created.errors?.[0]?.message).toEqual('Cannot create a custom field definition attached to entity types, use the entity type mutations');
    for (const key of ['entity_types', 'entity_type_settings']) {
      const edited = await queryAsAuthUser(CUSTOM_FIELDS_MANAGER, {
        query: CUSTOM_FIELD_PATCH,
        variables: { id: definitionId, input: [{ key, value: key === 'entity_types' ? ['Report'] : [] }] },
      });
      expect(edited.errors?.[0]?.message).toEqual('Cannot modify the entity types of a custom field definition, use the entity type mutations');
    }
  });

  it('should let Manage custom fields delete the custom field, but not Manage customization', async () => {
    expectForbidden(await queryAsAuthUser(CUSTOMIZATION_MANAGER, { query: CUSTOM_FIELD_DELETE, variables: { id: definitionId } }));
    const deleted = await queryAsAuthUser(CUSTOM_FIELDS_MANAGER, { query: CUSTOM_FIELD_DELETE, variables: { id: definitionId } });
    expect(deleted.errors).toBeUndefined();
    definitionId = '';
  });
});
