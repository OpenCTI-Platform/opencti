import { afterAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_DATA_COMPONENT, } from '../../../src/schema/stixDomainObject';
import { SYSTEM_USER } from '../../../src/utils/access';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../../src/modules/entitySetting/entitySetting-types';
import { validateInputCreation, validateInputUpdate } from '../../../src/schema/schema-validator';
import { resetCacheForEntity } from '../../../src/database/cache';

const CREATE_DATA_COMPONENT_QUERY = gql`
  mutation DataComponentAdd($input: DataComponentAddInput!) {
    dataComponentAdd(input: $input) {
      id
      standard_id
      name
      description
    }
  }
`;

const UPDATE_DATA_COMPONENT_QUERY = gql`
  mutation DataComponentEdit($id: ID!, $input: [EditInput]!) {
    dataComponentFieldPatch(id: $id, input: $input) {
      id
      name
      description
    }
  }
`;
const DELETE_DATA_COMPONENT_QUERY = gql`
  mutation dataComponentDelete($id: ID!) {
    dataSourceDelete(id: $id)
  }
`;

const READ_ENTITY_SETTING_QUERY_BY = gql`
  query entitySettingsByTargetType($targetType: String!) {
    entitySettingByType(targetType: $targetType) {
      id
    }
  }
`;

const UPDATE_ENTITY_SETTING_QUERY = gql`
  mutation entitySettingsEdit($ids: [ID!]!, $input: [EditInput!]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      id
    }
  }
`;

const updateEntitySetting = async (attributesConfiguration) => {
  const queryResult = await queryAsAdmin({
    query: READ_ENTITY_SETTING_QUERY_BY,
    variables: { targetType: ENTITY_TYPE_DATA_COMPONENT }
  });
  const entitySettingIdDataComponent = queryResult.data.entitySettingByType.id;

  await queryAsAdmin({
    query: UPDATE_ENTITY_SETTING_QUERY,
    variables: {
      ids: [entitySettingIdDataComponent],
      input: { key: 'attributes_configuration', value: [JSON.stringify(attributesConfiguration)] }
    },
  });
  resetCacheForEntity(ENTITY_TYPE_ENTITY_SETTING);
};

describe('Create and Update Validation', () => {
  const dataComponentStixId = 'data-component--934ab9db-49a9-4adb-9f1f-823d586928c0';
  it('should validate format schema attribute at creation', async () => {
    const attributesConfiguration = JSON.stringify([{ name: 'description', mandatory: true }]); // Valid JSON format for Entity Setting
    const entitySetting = { target_type: 'Data-Component', attributes_configuration: attributesConfiguration };
    await validateInputCreation(testContext, SYSTEM_USER, ENTITY_TYPE_ENTITY_SETTING, entitySetting, null);
  });

  it('should validate mandatory attributes at creation', async () => {
    // With value and without default value - description
    await updateEntitySetting([{ name: 'description', mandatory: true }]);

    let dataComponent = { name: 'entity name', description: 'My beautiful description', stix_id: dataComponentStixId };
    let queryResult = await queryAsAdmin({ query: CREATE_DATA_COMPONENT_QUERY, variables: { input: dataComponent } });
    expect(queryResult.data.dataComponentAdd.description).toEqual('My beautiful description');
    await queryAsAdmin({ query: DELETE_DATA_COMPONENT_QUERY, variables: { id: dataComponentStixId } });

    // Without value and with default value - description
    await updateEntitySetting([{ name: 'description', mandatory: true, default_values: ['test'] }]);

    dataComponent = { name: 'entity name', stix_id: dataComponentStixId };
    queryResult = await queryAsAdmin({ query: CREATE_DATA_COMPONENT_QUERY, variables: { input: dataComponent } });
    expect(queryResult.data.dataComponentAdd.description).toEqual('test');
    await queryAsAdmin({ query: DELETE_DATA_COMPONENT_QUERY, variables: { id: dataComponentStixId } });

    // With value and default value - description
    dataComponent = { name: 'entity name', description: 'description', stix_id: dataComponentStixId };
    queryResult = await queryAsAdmin({ query: CREATE_DATA_COMPONENT_QUERY, variables: { input: dataComponent } });
    expect(queryResult.data.dataComponentAdd.description).toEqual('description');
    await queryAsAdmin({ query: DELETE_DATA_COMPONENT_QUERY, variables: { id: dataComponentStixId } });
  });
  it('should invalidate mandatory attributes at creation', async () => {
    await updateEntitySetting([{ name: 'description', mandatory: true }]);

    const dataComponent = { name: 'entity name', stix_id: dataComponentStixId }; // Missed description
    const queryResult = await queryAsAdmin({ query: CREATE_DATA_COMPONENT_QUERY, variables: { input: dataComponent } });
    expect(queryResult.errors.length > 0).toBeTruthy();
    expect(queryResult.errors[0].extensions.data.message).toEqual('This attribute is mandatory');
  });

  it('should validate schema at update', async () => {
    const dataComponent = [{ key: 'description', value: ['description'], operation: 'replace' }];
    const dataComponentInitial = { name: 'initial name', confidence: 50 };
    await validateInputUpdate(testContext, SYSTEM_USER, ENTITY_TYPE_DATA_COMPONENT, dataComponentInitial, dataComponent, null);
  });

  it('should validate mandatory attributes at update', async () => {
    await updateEntitySetting([]);
    await queryAsAdmin({
      query: CREATE_DATA_COMPONENT_QUERY,
      variables: { input: { name: 'entity name', stix_id: dataComponentStixId } }
    });
    await updateEntitySetting([{ name: 'description', mandatory: true }]);

    const queryResult = await queryAsAdmin({
      query: UPDATE_DATA_COMPONENT_QUERY,
      variables: { id: dataComponentStixId, input: { key: 'description', value: ['50'] } },
    });
    expect(queryResult.data.dataComponentFieldPatch.description).toEqual('50');
  });
  it('should invalidate mandatory attributes at update', async () => {
    await updateEntitySetting([{ name: 'description', mandatory: true }]);

    const queryResult = await queryAsAdmin({
      query: UPDATE_DATA_COMPONENT_QUERY,
      variables: { id: dataComponentStixId, input: { key: 'description', value: [''] } },
    });
    expect(queryResult.errors.length > 0).toBeTruthy();
    expect(queryResult.errors[0].extensions.data.message).toEqual('This attribute is mandatory');
  });
  afterAll(async () => {
    await queryAsAdmin({ query: DELETE_DATA_COMPONENT_QUERY, variables: { id: dataComponentStixId } });
    await updateEntitySetting([]);
  });
});
