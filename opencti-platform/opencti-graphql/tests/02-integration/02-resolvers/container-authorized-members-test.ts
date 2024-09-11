import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import type { CaseIncident, EntitySettingEdge } from '../../../src/generated/graphql';
import {
  ADMIN_USER,
  adminQuery,
  editorQuery,
  getOrganizationIdByName,
  getUserIdByEmail,
  participantQuery,
  PLATFORM_ORGANIZATION,
  queryAsAdmin,
  securityQuery,
  USER_EDITOR
} from '../../utils/testQuery';
import { queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { executionContext, SYSTEM_USER } from '../../../src/utils/access';
import { initCreateEntitySettings } from '../../../src/modules/entitySetting/entitySetting-domain';
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
      currentUserAccessRight
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
      authorized_members {
        id
        access_right
      }
      currentUserAccessRight
    }
  }
`;

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

const DELETE_QUERY = gql`
  mutation CaseIncidentDelete($id: ID!) {
    caseIncidentDelete(id: $id)
  }
`;
const EDIT_AUTHORIZED_MEMBERS_QUERY = gql`
  mutation ContainerHeaderEditAuthorizedMembersMutation(
    $id: ID!
    $input: [MemberAccessInput!]
  ) {
    containerEdit(id: $id) {
      editAuthorizedMembers(input: $input) {
        authorized_members {
          id
          name
          entity_type
          access_right
        }
      }
    }
  }
`;

describe('Case Incident Response standard behavior with authorized_members activation from entity', () => {
  let caseIncidentResponseAuthorizedMembersFromEntity: CaseIncident;
  it('should Case Incident Response created', async () => {
    // Create Case Incident Response
    const caseIncidentResponseCreateQueryResult = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Case Incident Response With Authorized Members from entity'
        }
      }
    });

    expect(caseIncidentResponseCreateQueryResult).not.toBeNull();
    expect(caseIncidentResponseCreateQueryResult?.data?.caseIncidentAdd.authorized_members).not.toBeUndefined();
    expect(caseIncidentResponseCreateQueryResult?.data?.caseIncidentAdd.authorized_members).toEqual([]); // authorized members not activated
    expect(caseIncidentResponseCreateQueryResult?.data?.caseIncidentAdd.currentUserAccessRight).toEqual('admin'); // CurrentUser should be admin if authorized members not activated
    caseIncidentResponseAuthorizedMembersFromEntity = caseIncidentResponseCreateQueryResult?.data?.caseIncidentAdd;

    // Activate Authorized members
    await queryAsAdmin({
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: {
        id: caseIncidentResponseAuthorizedMembersFromEntity?.id,
        input: [
          {
            id: ADMIN_USER.id,
            access_right: 'admin'
          }
        ]
      }
    });
    // Verify if authorized members have been edited
    const caseIncidentResponseUpdatedQueryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: caseIncidentResponseAuthorizedMembersFromEntity.id }
    });
    expect(caseIncidentResponseUpdatedQueryResult).not.toBeNull();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.caseIncident.authorized_members).not.toBeUndefined();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.caseIncident.authorized_members).toEqual([
      {
        id: ADMIN_USER.id,
        access_right: 'admin'
      }
    ]);
  });
  it('should Case Incident Response get current User access right', async () => {
    // Add new authorized members
    const userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    await queryAsAdmin({
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: {
        id: caseIncidentResponseAuthorizedMembersFromEntity.id,
        input: [
          {
            id: ADMIN_USER.id,
            access_right: 'admin'
          },
          {
            id: userEditorId,
            access_right: 'view'
          }
        ]
      }
    });
    // Get current User access right
    const currentUserAccessRightQueryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: READ_QUERY,
      variables: { id: caseIncidentResponseAuthorizedMembersFromEntity.id },
    });
    expect(currentUserAccessRightQueryResult).not.toBeNull();
    expect(currentUserAccessRightQueryResult?.data?.caseIncident.currentUserAccessRight).toEqual('view');
  });
  it('should Case Incident Response deleted', async () => {
    // Delete the case
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: caseIncidentResponseAuthorizedMembersFromEntity.id },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseIncidentResponseAuthorizedMembersFromEntity.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).toBeNull();
  });
});

describe('Case Incident Response standard behavior with authorized_members activated via settings', () => {
  let caseIncidentResponseAuthorizedMembersFromSettings: CaseIncident;
  let entitySettingIdCaseIncidentResponse: string;
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
  it('should init entity settings', async () => {
    const ENTITY_SETTINGS_QUERY = gql`
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
    const context = executionContext('test');
    await initCreateEntitySettings(context, SYSTEM_USER);
    const queryResult = await adminQuery({ query: ENTITY_SETTINGS_QUERY });

    const entitySettingCaseIncidentResponse = queryResult.data?.entitySettings.edges
      .filter((entitySetting: EntitySettingEdge) => entitySetting.node.target_type === ENTITY_TYPE_CONTAINER_CASE_INCIDENT)[0];
    entitySettingIdCaseIncidentResponse = entitySettingCaseIncidentResponse?.node.id;
    expect(entitySettingIdCaseIncidentResponse).toBeTruthy();
  });
  it('should Case Incident Response created', async () => {
    // Activate authorized members for IR
    const authorizedMembersConfiguration = JSON.stringify([
      {
        name: 'authorized_members',
        default_values: [
          JSON.stringify({
            id: ADMIN_USER.id,
            access_right: 'admin'
          })
        ]
      }
    ]);
    const updateEntitySettingsResult = await adminQuery({
      query: ENTITY_SETTINGS_UPDATE_QUERY,
      variables: { ids: [entitySettingIdCaseIncidentResponse], input: { key: 'attributes_configuration', value: [authorizedMembersConfiguration] } },
    });
    expect(updateEntitySettingsResult.data?.entitySettingsFieldPatch?.[0]?.attributes_configuration).toEqual(authorizedMembersConfiguration);
    const caseIncidentResponseAuthorizedMembersData = await adminQuery({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Case Incident Response With Authorized Members via settings'
        }
      }
    });
    expect(caseIncidentResponseAuthorizedMembersData).not.toBeNull();
    expect(caseIncidentResponseAuthorizedMembersData?.data?.caseIncidentAdd.authorized_members).not.toBeUndefined();
    expect(caseIncidentResponseAuthorizedMembersData?.data?.caseIncidentAdd.authorized_members).toEqual([
      {
        id: ADMIN_USER.id,
        access_right: 'admin'
      }
    ]);
    caseIncidentResponseAuthorizedMembersFromSettings = caseIncidentResponseAuthorizedMembersData?.data?.caseIncidentAdd;
    // Clean
    const cleanAuthorizedMembersConfiguration = JSON.stringify([{ name: 'authorized_members', default_values: null }]);
    const cleanEntitySettingsResult = await adminQuery({
      query: ENTITY_SETTINGS_UPDATE_QUERY,
      variables: { ids: [entitySettingIdCaseIncidentResponse], input: { key: 'attributes_configuration', value: [cleanAuthorizedMembersConfiguration] } },
    });
    expect(cleanEntitySettingsResult.data?.entitySettingsFieldPatch?.[0]?.attributes_configuration).toEqual(cleanAuthorizedMembersConfiguration);
  });
  it('should Case Incident Response deleted', async () => {
    // Delete the case
    await adminQuery({
      query: DELETE_QUERY,
      variables: { id: caseIncidentResponseAuthorizedMembersFromSettings.id },
    });
    // Verify is no longer found
    const queryResult = await adminQuery({ query: READ_QUERY, variables: { id: caseIncidentResponseAuthorizedMembersFromSettings.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).toBeNull();
  });
});

describe('Case Incident Response and organization sharing standard behavior without platform organization', () => {
  let caseIrId: string;
  it('should Case Incident Response created', async () => {
    // Create Case Incident Response
    const caseIRCreateQueryResult = await adminQuery({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Case IR without platform Orga'
        }
      }
    });

    expect(caseIRCreateQueryResult).not.toBeNull();
    expect(caseIRCreateQueryResult?.data?.caseIncidentAdd.authorized_members).not.toBeUndefined();
    expect(caseIRCreateQueryResult?.data?.caseIncidentAdd.authorized_members).toEqual([]); // authorized members not activated
    caseIrId = caseIRCreateQueryResult?.data?.caseIncidentAdd.id;
  });
  it('should access Case Incident Response', async () => {
    const caseIRQueryResult = await securityQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(caseIRQueryResult?.data?.caseIncident.id).toEqual(caseIrId);
  });
  it('should Authorized Members activated', async () => {
    await queryAsAdmin({
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: {
        id: caseIrId,
        input: [
          {
            id: ADMIN_USER.id,
            access_right: 'admin'
          }
        ]
      }
    });
    // Verify if authorized members have been edited
    const caseIRUpdatedQueryResult = await adminQuery({
      query: READ_QUERY,
      variables: { id: caseIrId }
    });
    expect(caseIRUpdatedQueryResult).not.toBeNull();
    expect(caseIRUpdatedQueryResult?.data?.caseIncident.authorized_members).not.toBeUndefined();
    expect(caseIRUpdatedQueryResult?.data?.caseIncident.authorized_members).toEqual([
      {
        id: ADMIN_USER.id,
        access_right: 'admin'
      }
    ]);
  });
  it('should not access Case Incident Response if not in authorized members', async () => {
    const caseIRQueryResult = await securityQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(caseIRQueryResult?.data?.caseIncident).toBeNull();
  });
  it('should Case Incident Response deleted', async () => {
    // Delete the case
    await adminQuery({
      query: DELETE_QUERY,
      variables: { id: caseIrId },
    });
    // Verify is no longer found
    const queryResult = await adminQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).toBeNull();
  });
});

describe('Case Incident Response and organization sharing standard behavior with platform organization', () => {
  let testOrganizationId: string;
  let caseIrId: string;
  let userEditorId: string;
  let settingsInternalId: string;
  const PLATFORM_ORGANIZATION_QUERY = gql`
    mutation PoliciesFieldPatchMutation($id: ID!, $input: [EditInput]!) {
      settingsEdit(id: $id) {
        fieldPatch(input: $input) {
          platform_organization {
            id
            name
          }
          enterprise_edition
          id
        }
      }
    }
  `;
  it('should plateform organization sharing and EE activated', async () => {
    // Get organization id
    testOrganizationId = await getOrganizationIdByName(PLATFORM_ORGANIZATION.name);

    // Get settings ID
    const SETTINGS_READ_QUERY = gql`
      query settings {
        settings {
          id
          platform_organization {
            id
            name
          }
        }
      }
    `;
    const queryResult = await adminQuery({ query: SETTINGS_READ_QUERY, variables: {} });
    settingsInternalId = queryResult.data?.settings?.id;

    // Set plateform organization
    const platformOrganization = await adminQuery({
      query: PLATFORM_ORGANIZATION_QUERY,
      variables: {
        id: settingsInternalId,
        input: [
          { key: 'platform_organization', value: testOrganizationId },
          { key: 'enterprise_edition', value: new Date().getTime() },
        ]
      }
    });

    expect(platformOrganization).not.toBeNull();
    expect(platformOrganization?.data?.settingsEdit.fieldPatch.platform_organization).not.toBeUndefined();
    expect(platformOrganization?.data?.settingsEdit.fieldPatch.enterprise_edition).not.toBeUndefined();
    expect(platformOrganization?.data?.settingsEdit.fieldPatch.platform_organization.name).toEqual(PLATFORM_ORGANIZATION.name);
  });
  it('should Case Incident Response created', async () => {
    // Create Case Incident Response
    const caseIRCreateQueryResult = await adminQuery({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Case IR with platform orga'
        }
      }
    });

    expect(caseIRCreateQueryResult).not.toBeNull();
    expect(caseIRCreateQueryResult?.data?.caseIncidentAdd.authorized_members).not.toBeUndefined();
    expect(caseIRCreateQueryResult?.data?.caseIncidentAdd.authorized_members).toEqual([]); // authorized members not activated
    caseIrId = caseIRCreateQueryResult?.data?.caseIncidentAdd.id;
  });
  it('should not access Case Incident Response if no organization', async () => {
    const caseIRQueryResult = await participantQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult.data?.caseIncident).toBeNull();
  });
  it('should not access Case Incident Response from different organization', async () => {
    const caseIRQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult.data?.caseIncident).toBeNull();
  });
  it('should Authorized Members activated', async () => {
    userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    await queryAsAdmin({
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: {
        id: caseIrId,
        input: [
          {
            id: ADMIN_USER.id,
            access_right: 'admin'
          },
          {
            id: userEditorId,
            access_right: 'view'
          }
        ]
      }
    });
    // Verify if authorized members have been edited
    const caseIRUpdatedQueryResult = await adminQuery({
      query: READ_QUERY,
      variables: { id: caseIrId }
    });
    expect(caseIRUpdatedQueryResult).not.toBeNull();
    expect(caseIRUpdatedQueryResult?.data?.caseIncident.authorized_members).not.toBeUndefined();
    expect(caseIRUpdatedQueryResult?.data?.caseIncident.authorized_members).toEqual([
      {
        id: ADMIN_USER.id,
        access_right: 'admin'
      },
      {
        id: userEditorId,
        access_right: 'view'
      }
    ]);
  });
  it('should access Case Incident Response out of her organization if authorized members activated', async () => {
    const caseIRQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(caseIRQueryResult?.data?.caseIncident.id).toEqual(caseIrId);
  });
  it('should plateform organization sharing and EE deactivated', async () => {
    // Remove plateform organization
    const platformOrganization = await adminQuery({
      query: PLATFORM_ORGANIZATION_QUERY,
      variables: { id: settingsInternalId,
        input: [
          { key: 'platform_organization', value: [] },
          { key: 'enterprise_edition', value: [] },
        ] }
    });
    expect(platformOrganization).not.toBeNull();
    expect(platformOrganization?.data?.settingsEdit.fieldPatch.platform_organization).toBeNull();
  });
  it('should Case Incident Response deleted', async () => {
    // Delete the case
    await adminQuery({
      query: DELETE_QUERY,
      variables: { id: caseIrId },
    });
    // Verify is no longer found
    const queryResult = await adminQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).toBeNull();
  });
});