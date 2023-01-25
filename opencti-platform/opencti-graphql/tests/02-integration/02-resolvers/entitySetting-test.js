import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { initCreateEntitySettings } from '../../../src/modules/entitySetting/entitySetting-domain';
import { executionContext } from '../../../src/utils/access';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../../src/schema/general';

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
  let entitySettingIdCoreRelationship;
  it('should init entity settings', async () => {
    const context = executionContext('test');
    await initCreateEntitySettings(context);
    const queryResult = await queryAsAdmin({ query: LIST_QUERY });
    expect(queryResult.data.entitySettings.edges.length).toEqual(34);

    const entitySettingDataComponent = queryResult.data.entitySettings.edges.filter((entitySetting) => entitySetting.node.target_type === ABSTRACT_STIX_CORE_RELATIONSHIP)[0];
    expect(entitySettingDataComponent.platform_entity_files_ref).toSatisfy((s) => s === null || s === undefined);
    entitySettingIdCoreRelationship = entitySettingDataComponent.node.id;
  });
  it('should retrieve entity setting by id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY_BY_ID, variables: { id: entitySettingIdCoreRelationship } });
    expect(queryResult.data.entitySetting.target_type).toEqual(ABSTRACT_STIX_CORE_RELATIONSHIP);
    expect(queryResult.data.entitySetting.platform_entity_files_ref).toSatisfy((s) => s === null || s === undefined);
    expect(queryResult.data.entitySetting.platform_hidden_type).toBeFalsy();
  });
  it('should retrieve entity setting by target type', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY_BY_TARGET_TYPE, variables: { targetType: ABSTRACT_STIX_CORE_RELATIONSHIP } });
    expect(queryResult.data.entitySettingByType.target_type).toEqual(ABSTRACT_STIX_CORE_RELATIONSHIP);
    expect(queryResult.data.entitySettingByType.platform_entity_files_ref).toSatisfy((s) => s === null || s === undefined);
    expect(queryResult.data.entitySettingByType.platform_hidden_type).toBeFalsy();
  });
  it('should update entity setting by id - valid', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdCoreRelationship], input: { key: 'enforce_reference', value: ['true'] } },
    });
    expect(queryResult.data.entitySettingsFieldPatch[0].enforce_reference).toBeTruthy();
  });
  it('should update entity setting by id - invalid option setting', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdCoreRelationship], input: { key: 'platform_entity_files_ref', value: ['true'] } },
    });
    expect(queryResult.errors.length > 0).toBeTruthy();
  });
  it('should mass update entity settings by ids - valid', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdCoreRelationship], input: { key: 'enforce_reference', value: ['true'] } },
    });
    const entityTypeDataComponent = queryResult.data.entitySettingsFieldPatch.filter((entityType) => entityType.target_type === ABSTRACT_STIX_CORE_RELATIONSHIP)[0];
    expect(entityTypeDataComponent.enforce_reference).toBeTruthy();
  });
  it('should mass update entity settings by ids - invalid option setting', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingIdCoreRelationship], input: { key: 'platform_entity_files_ref', value: ['true'] } },
    });
    expect(queryResult.errors.length > 0).toBeTruthy();
  });
});
