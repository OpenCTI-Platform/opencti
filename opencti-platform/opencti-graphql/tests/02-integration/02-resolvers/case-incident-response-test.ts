import { describe, it, expect } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin } from '../../utils/testQuery';
import type { CaseIncident } from '../../../src/generated/graphql';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';

const CREATE_QUERY = gql`
  mutation CaseIncidentAdd($input: CaseIncidentAddInput!) {
    caseIncidentAdd(input: $input){
      id
      standard_id
      name
      description
      authorized_members {
        id
        access_right
      }
    }
  }
`;

const READ_QUERY = gql`
  query caseIncident($id: String!) {
    caseIncident(id: $id) {
      id
      standard_id
      name
      description
      toStix
      authorized_members {
        id
      }
    }
  }
`;

const DELETE_QUERY = gql`
  mutation CaseIncidentDelete($id: ID!) {
    caseIncidentDelete(id: $id)
  }
`;

describe('Case Incident Response resolver standard behavior', () => {
  let caseIncidentResponse: CaseIncident;
  it('should Case Incident Response created', async () => {
    const caseIncidentResponseData = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Case Incident Response'
        }
      }
    });
    expect(caseIncidentResponseData).not.toBeNull();
    expect(caseIncidentResponseData?.data?.caseIncidentAdd.authorized_members).not.toBeUndefined();
    expect(caseIncidentResponseData?.data?.caseIncidentAdd.authorized_members).toEqual([]); // authorized members not activated
    caseIncidentResponse = caseIncidentResponseData?.data?.caseIncidentAdd;
  });
  it('should Case Incident Response loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseIncidentResponse.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).not.toBeNull();
    expect(queryResult?.data?.caseIncident.id).toEqual(caseIncidentResponse.id);
    expect(queryResult?.data?.caseIncident.toStix.length).toBeGreaterThan(5);
  });
  it('should Case Incident Response loaded by standard id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseIncidentResponse.standard_id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).not.toBeNull();
    expect(queryResult?.data?.caseIncident.id).toEqual(caseIncidentResponse.id);
  });
  it('should list Case Incident Response', async () => {
    const LIST_QUERY = gql`
      query caseIncidents(
        $first: Int
        $after: ID
        $orderBy: CaseIncidentsOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
        $search: String
        $toStix: Boolean
      ) {
        caseIncidents(
          first: $first
          after: $after
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
          search: $search
          toStix: $toStix
        ) {
          edges {
            node {
              id
              standard_id
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult?.data?.caseIncidents.edges.length).toEqual(1);
  });
  it('should update Case Incident Response', async () => {
    const UPDATE_QUERY = gql`
      mutation CaseIncident($id: ID!, $input: [EditInput]!) {
        stixDomainObjectEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            ... on Case {
              name
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: caseIncidentResponse.id, input: { key: 'name', value: ['Case - updated'] } },
    });
    expect(queryResult?.data?.stixDomainObjectEdit.fieldPatch.name).toEqual('Case - updated');
  });
  // TODO ADD context test even if i don't understand what it is?
  it('should Case Incident Response deleted', async () => {
    // Delete the case
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: caseIncidentResponse.id },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseIncidentResponse.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).toBeNull();
  });
});

describe('Case Incident Response authorized_members standard behavior', () => {
  let caseIncidentResponseAuthorizedMembers: CaseIncident;
  it('should Case Incident Response created with authorized_members activated via settings', async () => {
    // Activate authorized members for IR
    const ENTITY_SETTINGS_READ_QUERY_BY_TARGET_TYPE = gql`
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

    const ENTITY_SETTINGS_UPDATE_QUERY = gql`
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

    const caseIncidentResponseSettingsQueryResult = await queryAsAdmin({
      query: ENTITY_SETTINGS_READ_QUERY_BY_TARGET_TYPE,
      variables: { targetType: ENTITY_TYPE_CONTAINER_CASE_INCIDENT }
    });
    expect(caseIncidentResponseSettingsQueryResult.data?.entitySettingByType.target_type).toEqual(ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    const caseIncidentEntitySetting = caseIncidentResponseSettingsQueryResult.data?.entitySettingByType;

    const authorizedMembersConfiguration = JSON.stringify([{ name: 'authorized_members', default_values: [{ id: ADMIN_USER.id, access_right: 'admin' }] }]);

    const updateEntitySettingsResult = await queryAsAdmin({
      query: ENTITY_SETTINGS_UPDATE_QUERY,
      variables: { ids: [caseIncidentEntitySetting.id], input: { key: 'attributes_configuration', value: [authorizedMembersConfiguration] } },
    });
    expect(updateEntitySettingsResult.data?.entitySettingsFieldPatch[0].attribute_configuration).toEqual([authorizedMembersConfiguration]);

    const caseIncidentResponseAuthorizedMembersData = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Case Incident Response With Authorized Members'
        }
      }
    });
    expect(caseIncidentResponseAuthorizedMembersData).not.toBeNull();
    expect(caseIncidentResponseAuthorizedMembersData?.data?.caseIncidentAdd.authorized_members).not.toBeUndefined();
    expect(caseIncidentResponseAuthorizedMembersData?.data?.caseIncidentAdd.authorized_members).toEqual([
      {
        id: ADMIN_USER.id,
        name: ADMIN_USER.name,
        access_right: 'admin'
      }
    ]);
    caseIncidentResponseAuthorizedMembers = caseIncidentResponseAuthorizedMembersData?.data?.caseIncidentAdd;
    // Clean
    await queryAsAdmin({
      query: ENTITY_SETTINGS_UPDATE_QUERY,
      variables: { ids: [caseIncidentEntitySetting.id], input: { key: 'attributes_configuration', value: [] } },
    });
  });
  it('should Case Incident Response deleted', async () => {
    // Delete the case
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: caseIncidentResponseAuthorizedMembers.id },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseIncidentResponseAuthorizedMembers.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).toBeNull();
  });
});
