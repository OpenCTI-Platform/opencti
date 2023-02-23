import { describe, expect, it, afterAll } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_DATA_COMPONENT, } from '../../../src/schema/stixDomainObject';
import { SYSTEM_USER } from '../../../src/utils/access';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../../src/modules/entitySetting/entitySetting-types';
import { validateInputCreation, validateInputUpdate } from '../../../src/schema/schema-validator';

const CREATE_QUERY = gql`
  mutation DataComponentAdd($input: DataComponentAddInput!) {
    dataComponentAdd(input: $input) {
      id
      standard_id
      name
      description
    }
  }
`;

const UPDATE_QUERY = gql`
  mutation DataComponentEdit($id: ID!, $input: [EditInput]!) {
    dataComponentFieldPatch(id: $id, input: $input) {
      id
      name
    }
  }
`;

describe('Create and Update Validation', () => {
  const dataComponentStixId = 'data-component--934ab9db-49a9-4adb-9f1f-823d586928c0';
  it('should validate format schema attribute at creation', async () => {
    const attributesConfiguration = JSON.stringify([{ name: 'description', mandatory: true }]); // Valid JSON format for Entity Setting
    const entitySetting = { target_type: 'Data-Component', attributes_configuration: attributesConfiguration };
    await validateInputCreation(testContext, SYSTEM_USER, ENTITY_TYPE_ENTITY_SETTING, entitySetting, null);
  });
  it('should invalidate format schema attribute at creation', async () => {
    const attributesConfiguration = JSON.stringify([{ alias: 'confidence', mandatory: true }]); // Invalid JSON format for Entity Setting
    const entitySetting = { target_type: 'Data-Component', attributes_configuration: attributesConfiguration };
    await expect(validateInputCreation(testContext, SYSTEM_USER, ENTITY_TYPE_ENTITY_SETTING, entitySetting, null)).rejects.toThrow();
  });

  it('should validate mandatory attributes at creation', async () => {
    const attributesConfiguration = JSON.stringify([{ name: 'confidence', mandatory: true }, { name: 'x_opencti_workflow_id', mandatory: false }]); // Valid attributes for Data Component
    const entitySetting = { target_type: 'Data-Component', attributes_configuration: attributesConfiguration };
    const dataComponent = { name: 'entity name', confidence: 50, stix_id: dataComponentStixId };
    await validateInputCreation(testContext, SYSTEM_USER, ENTITY_TYPE_DATA_COMPONENT, dataComponent, entitySetting);

    await queryAsAdmin({ query: CREATE_QUERY, variables: dataComponent });
  });
  it('should invalidate mandatory attributes at creation', async () => {
    const attributesConfiguration = JSON.stringify([{ name: 'confidence', mandatory: true }, { name: 'x_opencti_workflow_id', mandatory: false }]); // Valid attributes for Data Component
    const entitySetting = { target_type: 'Data-Component', attributes_configuration: attributesConfiguration };
    const dataComponent = { name: 'entity name', stix_id: dataComponentStixId }; // Missed confidence
    await expect(validateInputCreation(testContext, SYSTEM_USER, ENTITY_TYPE_DATA_COMPONENT, dataComponent, entitySetting)).rejects.toThrow();

    const queryResult = await queryAsAdmin({ query: CREATE_QUERY, variables: dataComponent });
    expect(queryResult.errors.length > 0).toBeTruthy();
  });

  it('should validate schema at update', async () => {
    const dataComponent = { description: 'description' };
    const dataComponentInitial = { name: 'initial name', confidence: 50 };
    await validateInputUpdate(testContext, SYSTEM_USER, ENTITY_TYPE_DATA_COMPONENT, dataComponent, null, dataComponentInitial);
  });

  it('should validate mandatory attributes at update', async () => {
    const attributesConfiguration = JSON.stringify([{ name: 'confidence', mandatory: true }, { name: 'x_opencti_workflow_id', mandatory: false }]); // Valid attributes for Data Component
    const entitySetting = { target_type: 'Data-Component', attributes_configuration: attributesConfiguration };
    const dataComponent = { name: 'update name' };
    const dataComponentInitial = { name: 'initial name', confidence: 50, stix_id: dataComponentStixId };
    await validateInputUpdate(testContext, SYSTEM_USER, ENTITY_TYPE_DATA_COMPONENT, dataComponent, entitySetting, dataComponentInitial);

    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: dataComponentStixId, input: { key: 'name', value: ['update name'] } },
    });
  });
  it('should invalidate mandatory attributes at update', async () => {
    const attributesConfiguration = JSON.stringify([{ name: 'confidence', mandatory: true }]); // Valid attributes for Data Component
    const entitySetting = { target_type: 'Data-Component', attributes_configuration: attributesConfiguration };
    const dataComponent = { confidence: '' }; // Missed confidence
    const dataComponentInitial = { name: 'initial name', confidence: 50, stix_id: dataComponentStixId };
    await expect(validateInputUpdate(testContext, SYSTEM_USER, ENTITY_TYPE_DATA_COMPONENT, dataComponent, entitySetting, dataComponentInitial)).rejects.toThrow();

    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: dataComponentStixId, input: { key: 'confidence', value: [''] } },
    });
    expect(queryResult.errors.length > 0).toBeTruthy();
  });
  afterAll(async () => {
    const DELETE_QUERY = gql`
      mutation dataComponentDelete($id: ID!) {
        dataSourceDelete(id: $id)
      }
    `;
    await queryAsAdmin({ query: DELETE_QUERY, variables: { id: dataComponentStixId } });
  });
});
