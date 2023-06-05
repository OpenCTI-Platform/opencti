import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { initCreateEntitySettings } from '../../../src/modules/entitySetting/entitySetting-domain';
import { executionContext } from '../../../src/utils/access';
import { ENTITY_TYPE_CONTAINER_NOTE } from '../../../src/schema/stixDomainObject';

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
    }
  }
`;

describe('EntitySetting resolver standard behavior', () => {
  let entitySettingIdNote;
  it('should init entity settings', async () => {
    const context = executionContext('test');
    await initCreateEntitySettings(context);
    const queryResult = await queryAsAdmin({ query: LIST_QUERY });
    expect(queryResult.data.entitySettings.edges.length).toEqual(39);

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
  it('should update entity settings by ids - valid', async () => {
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
  });
  it('should update entity settings by ids - invalid mandatory attributes', async () => {
    const attributesConfiguration = JSON.stringify([{ name: 'newfield', mandatory: true }]);
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdNote], input: { attributes_configuration: attributesConfiguration } },
    });
    expect(queryResult.errors.length > 0).toBeTruthy();
  });
});
