import { beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { initCreateEntitySettings } from '../../../src/modules/entitySetting/entitySetting-domain';
import { executionContext, SYSTEM_USER } from '../../../src/utils/access';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import { entitiesCounter } from '../../02-dataInjection/01-dataCount/entityCountHelper';

const LIST_QUERY = gql`
  query entitySettings {
    entitySettings {
      edges {
        node {
          id
          target_type
          platform_entity_files_ref
          platform_hidden_type
          enforce_reference
        }
      }
    }
  }
`;
const READ_QUERY_BY_ID = gql`
  query entitySetting($id: String!) {
    entitySetting(id: $id) {
      id
      target_type
      platform_entity_files_ref
      platform_hidden_type
      enforce_reference
    }
  }
`;
const READ_QUERY_BY_TARGET_TYPE = gql`
  query entitySettingsByTargetType($targetType: String!) {
    entitySettingByType(targetType: $targetType) {
      id
      target_type
      platform_entity_files_ref
      platform_hidden_type
      enforce_reference
    }
  }
`;
const UPDATE_QUERY = gql`
  mutation entitySettingsEdit($ids: [ID!]!, $input: [EditInput!]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      id
      target_type
      platform_entity_files_ref
      platform_hidden_type
      enforce_reference
      attributes_configuration
    }
  }
`;

describe('EntitySetting resolver standard behavior', () => {
  let entitySettingIdNote;
  it('should init entity settings', async () => {
    const context = executionContext('test');
    await initCreateEntitySettings(context, SYSTEM_USER);
    const queryResult = await queryAsAdmin({ query: LIST_QUERY });
    expect(queryResult.data.entitySettings.edges.length).toEqual(entitiesCounter.EntitySetting);

    const entitySettingNote = queryResult.data.entitySettings.edges.filter((entitySetting) => entitySetting.node.target_type === ENTITY_TYPE_CONTAINER_NOTE)[0];
    expect(entitySettingNote.platform_entity_files_ref).toBeFalsy();
    entitySettingIdNote = entitySettingNote.node.id;
  });
  it('should retrieve entity setting by id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY_BY_ID, variables: { id: entitySettingIdNote } });
    expect(queryResult.data.entitySetting.target_type).toEqual(ENTITY_TYPE_CONTAINER_NOTE);
    expect(queryResult.data.entitySetting.platform_entity_files_ref).toBeFalsy();
    expect(queryResult.data.entitySetting.platform_hidden_type).toBeFalsy();
    expect(queryResult.data.entitySetting.enforce_reference).toSatisfy((s) => s === null || s === undefined);
  });
  it('should retrieve entity setting by target type', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY_BY_TARGET_TYPE, variables: { targetType: ENTITY_TYPE_CONTAINER_NOTE } });
    expect(queryResult.data.entitySettingByType.target_type).toEqual(ENTITY_TYPE_CONTAINER_NOTE);
    expect(queryResult.data.entitySettingByType.platform_entity_files_ref).toBeFalsy();
    expect(queryResult.data.entitySettingByType.platform_hidden_type).toBeFalsy();
    expect(queryResult.data.entitySettingByType.enforce_reference).toSatisfy((s) => s === null || s === undefined);
  });
  it('should update entity settings by ids - valid option setting', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdNote], input: { key: 'platform_entity_files_ref', value: ['true'] } },
    });
    const entityTypeDataComponent = queryResult.data.entitySettingsFieldPatch.filter((entityType) => entityType.target_type === ENTITY_TYPE_CONTAINER_NOTE)[0];
    expect(entityTypeDataComponent.platform_entity_files_ref).toBeTruthy();
    // Clean
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdNote], input: { key: 'platform_entity_files_ref', value: ['false'] } },
    });
  });
  it('should update entity settings by ids - invalid option setting', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdNote], input: { key: 'enforce_reference', value: ['true'] } },
    });
    expect(queryResult.errors.length > 0).toBeTruthy();
    expect(queryResult.errors[0].message).toEqual('This setting is not available for this entity');
  });
  it('should update entity settings by ids - valid mandatory attributes', async () => {
    const attributesConfiguration = JSON.stringify([{ name: 'attribute_abstract', mandatory: true }]);
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdNote], input: { key: 'attributes_configuration', value: [attributesConfiguration] } },
    });
    const entityTypeDataComponent = queryResult.data.entitySettingsFieldPatch.filter((entityType) => entityType.target_type === ENTITY_TYPE_CONTAINER_NOTE)[0];
    expect(entityTypeDataComponent.attributes_configuration).not.toBeNull();
    // Clean
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdNote], input: { key: 'attributes_configuration', value: [attributesConfiguration] } },
    });
  });
  it('should update entity settings by ids - invalid mandatory attributes', async () => {
    const attributesConfiguration = JSON.stringify([{ name: 'newfield', mandatory: true }]);
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdNote], input: { key: 'attributes_configuration', value: [attributesConfiguration] } },
    });
    expect(queryResult.errors.length > 0).toBeTruthy();
    expect(queryResult.errors[0].message).toEqual('This attribute is not customizable for this entity');
  });
  it('should update entity settings by ids - valid default value', async () => {
    const attributesConfiguration = JSON.stringify([{ name: 'createdBy', default_values: ['identity--d37acc64-4a6f-4dc2-879a-a4c138d0a27f'] }]);
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdNote], input: { key: 'attributes_configuration', value: [attributesConfiguration] } },
    });
    const entityTypeDataComponent = queryResult.data.entitySettingsFieldPatch.filter((entityType) => entityType.target_type === ENTITY_TYPE_CONTAINER_NOTE)[0];
    expect(entityTypeDataComponent.attributes_configuration).not.toBeNull();
    // Clean
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdNote], input: { key: 'attributes_configuration', value: [] } },
    });
  });
});

// -- ATTRIBUTES DEFINITIONS --

const READ_ATTRIBUTES_DEFINITION_QUERY_BY_TARGET_TYPE = gql`
  query entitySettingsByTargetType($targetType: String!) {
    entitySettingByType(targetType: $targetType) {
      id
      attributesDefinitions {
        name
        type
        mandatoryType
        multiple
        mandatory
        label
        defaultValues {
          id
          name
        }
        scale
      }
    }
  }
`;

describe('EntitySetting resolver - attributes definitions', () => {
  it('should retrieve attributes definition', async () => {
    const queryResult = await queryAsAdmin({ query: READ_ATTRIBUTES_DEFINITION_QUERY_BY_TARGET_TYPE, variables: { targetType: ENTITY_TYPE_CONTAINER_NOTE } });
    const { attributesDefinitions } = queryResult.data.entitySettingByType;
    const attributes = [...schemaAttributesDefinition.getAttributes(ENTITY_TYPE_CONTAINER_NOTE).values()]
      .filter((attr) => attr.editDefault);
    const refs = schemaRelationsRefDefinition.getRelationsRef(ENTITY_TYPE_CONTAINER_NOTE)
      .filter((ref) => ref.mandatoryType === 'customizable' || ref.mandatoryType === 'external');
    expect(attributesDefinitions.length).toEqual(attributes.length + refs.length);
  });
});

// -- CUSTOM NAME --

const READ_CUSTOM_NAME_QUERY = gql`
  query EntitySettingsByTargetTypeCustomName($targetType: String!) {
    entitySettingByType(targetType: $targetType) {
      id
      custom_name
      custom_name_plural
    }
  }
`;

const UPDATE_CUSTOM_NAME_QUERY = gql`
  mutation EntitySettingsEditCustomName($ids: [ID!]!, $input: [EditInput!]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      id
      custom_name
      custom_name_plural
    }
  }
`;

describe('EntitySetting resolver - custom name', () => {
  let entitySettingReportId;
  beforeAll(async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY });
    const entitySettingReport = queryResult.data.entitySettings.edges.filter((entitySetting) => entitySetting.node.target_type === ENTITY_TYPE_CONTAINER_REPORT)[0];
    entitySettingReportId = entitySettingReport.node.id;
  });

  it('should retrieve null custom name by default', async () => {
    const queryResult = await queryAsAdmin({ query: READ_CUSTOM_NAME_QUERY, variables: { targetType: ENTITY_TYPE_CONTAINER_REPORT } });
    const { custom_name, custom_name_plural } = queryResult.data.entitySettingByType;
    expect(custom_name).toEqual(null);
    expect(custom_name_plural).toEqual(null);
  });

  it('should update custom name (singular and plural)', async () => {
    const customReportName = 'Dossier';
    const queryResult = await queryAsAdmin({
      query: UPDATE_CUSTOM_NAME_QUERY,
      variables: { ids: [entitySettingReportId], input: { key: 'custom_name', value: customReportName } },
    });
    const updatedEntitySetting = queryResult.data.entitySettingsFieldPatch.filter((entityType) => entityType.id === entitySettingReportId)[0];
    expect(updatedEntitySetting.custom_name).toBe(customReportName);
    // Clean
    await queryAsAdmin({
      query: UPDATE_CUSTOM_NAME_QUERY,
      variables: { ids: [entitySettingReportId], input: { key: 'custom_name', value: null } },
    });
  });
});
