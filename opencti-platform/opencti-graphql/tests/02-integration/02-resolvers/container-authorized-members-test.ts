import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import type { CaseIncident, EntitySettingEdge } from '../../../src/generated/graphql';
import {
  ADMIN_USER,
  adminQuery,
  editorQuery,
  getOrganizationIdByName,
  getUserIdByEmail,
  PLATFORM_ORGANIZATION,
  securityQuery,
  TEST_ORGANIZATION,
  USER_EDITOR,
  USER_SECURITY
} from '../../utils/testQuery';
import { adminQueryWithSuccess, disableEE, enableCEAndUnSetOrganization, enableEE, enableEEAndSetOrganization, queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';
import conf from '../../../src/config/conf';
import { authorizedMembers } from '../../../src/schema/attribute-definition';

const CREATE_QUERY = gql`
  mutation CaseIncidentAdd($input: CaseIncidentAddInput!) {
    caseIncidentAdd(input: $input){
      id
      standard_id
      name
      description
      authorized_members {
        member_id
        access_right
      }
      currentUserAccessRight
    }
  }
`;

const CREATE_REPORT_QUERY = gql`
  mutation ReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
      name
      standard_id
    }
  }
`;

const READ_QUERY = gql`
  query caseIncident($id: String!) {
    caseIncident(id: $id) {
      id
      standard_id
      name
      authorized_members {
        member_id
        access_right
      }
      currentUserAccessRight
    }
  }
`;

const READ_REPORT_QUERY = gql`
  query report($id: String!) {
    report(id: $id) {
      id
      standard_id
      name
      authorized_members {
        member_id
        access_right
      }
      currentUserAccessRight
    }
  }
`;

const DELETE_QUERY = gql`
  mutation CaseIncidentDelete($id: ID!) {
    caseIncidentDelete(id: $id)
  }
`;

const DELETE_REPORT_QUERY = gql`
  mutation reportDelete($id: ID!) {
    reportEdit(id: $id) {
      delete
    }
  }
`;

const UPDATE_QUERY = gql`
  mutation CaseIncident($id: ID!, $input: [EditInput]!) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        ... on Case {
          currentUserAccessRight
          name
        }
      }
    }
  }
`;

const EDIT_AUTHORIZED_MEMBERS_QUERY = gql`
  mutation ContainerHeaderEditAuthorizedMembersMutation(
    $id: ID!
    $input: [MemberAccessInput!]
  ) {
    containerEdit(id: $id) {
      editAuthorizedMembers(input: $input) {
        id
        currentUserAccessRight
        authorized_members {
          member_id
          access_right
        }
        authorized_members_activation_date
      }
    }
  }
`;

const PLATFORM_ORGANIZATION_QUERY = gql`
  mutation PoliciesFieldPatchMutation($id: ID!, $input: [EditInput]!) {
      settingsEdit(id: $id) {
          fieldPatch(input: $input) {
              id
              platform_organization {
                  id
                  name
              }
              platform_enterprise_edition {
                  license_enterprise
                  license_validated
              }
          }
      }
  }
`;

const ORGANIZATION_SHARING_QUERY = gql`
  mutation StixCoreObjectSharingGroupAddMutation(
    $id: ID!
    $organizationId: ID!
  ) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId) {
        id
        objectOrganization {
          id
          name
        }
      }
    }
  }
`;

const LIST_RESTRICTED_ENTITIES = gql`
  query stixCoreObjectsRestricted {
    stixCoreObjectsRestricted {
      edges {
        node {
          id
          entity_type
        }
      }
    }
  }
`;

describe('Case Incident Response standard behavior with authorized_members activation from entity', () => {
  let caseIncident: CaseIncident;
  let userEditorId: string;
  it('should Case Incident Response created', async () => {
    // Create Case Incident Response
    const caseIncidentResponseCreateQueryResult = await adminQuery({
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
    caseIncident = caseIncidentResponseCreateQueryResult?.data?.caseIncidentAdd;
  });
  it('should Editor user access Case Incident Response', async () => {
    const caseIRQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIncident.id } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(caseIRQueryResult?.data?.caseIncident.id).toEqual(caseIncident.id);
    expect(caseIRQueryResult?.data?.caseIncident.currentUserAccessRight).toEqual('admin');
  });
  it('should SECURITY user not edit authorized members because missing capa', async () => {
    userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    const restrictedMembers = {
      id: caseIncident.id,
      input: [
        {
          id: userEditorId,
          access_right: 'view'
        },
      ]
    };
    await queryAsUserIsExpectedForbidden(USER_SECURITY.client, {
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: restrictedMembers,
    });
  });
  it('should Admin user edit authorized members', async () => {
    // Activate Authorized members
    const caseIncidentResponseUpdatedQueryResult = await adminQuery({
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: {
        id: caseIncident?.id,
        input: [
          {
            id: ADMIN_USER.id,
            access_right: 'admin'
          }
        ]
      }
    });
    expect(caseIncidentResponseUpdatedQueryResult).not.toBeNull();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).not.toBeUndefined();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).toEqual([
      {
        member_id: ADMIN_USER.id,
        access_right: 'admin'
      }
    ]);
  });
  it('should Editor user not access Case Incident Response', async () => {
    const caseIRQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIncident.id } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(caseIRQueryResult?.data?.caseIncident).toBeNull();
  });
  it('should Admin user edit authorized members: Editor has view access right', async () => {
    // Add Editor user in authorized members
    const caseIncidentResponseUpdatedQueryResult = await adminQuery({
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: {
        id: caseIncident.id,
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
    expect(caseIncidentResponseUpdatedQueryResult).not.toBeNull();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.containerEdit).not.toBeNull();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).not.toBeNull();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).not.toBeUndefined();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).toEqual([
      {
        member_id: ADMIN_USER.id,
        access_right: 'admin'
      },
      {
        member_id: userEditorId,
        access_right: 'view'
      }
    ]);
  });
  it('should Editor user access Case Incident Response', async () => {
    const caseIRQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIncident.id } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(caseIRQueryResult?.data?.caseIncident.id).toEqual(caseIncident.id);
    expect(caseIRQueryResult?.data?.caseIncident.currentUserAccessRight).toEqual('view');
  });
  it('should Editor user not edit case incident with view access right', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: UPDATE_QUERY,
      variables: { id: caseIncident.id, input: { key: 'name', value: ['Case Incident Response - updated'] } },
    });
  });
  it('should Admin user edit authorized members: Editor has edit access right', async () => {
    const caseIncidentResponseUpdatedQueryResult = await adminQuery({
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: {
        id: caseIncident.id,
        input: [
          {
            id: ADMIN_USER.id,
            access_right: 'admin'
          },
          {
            id: userEditorId,
            access_right: 'edit'
          }
        ]
      }
    });
    expect(caseIncidentResponseUpdatedQueryResult).not.toBeNull();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).not.toBeUndefined();
    // edit access can't see authorized_members list
    const editorQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIncident.id } });
    expect(editorQueryResult).not.toBeNull();
    expect(editorQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(editorQueryResult?.data?.caseIncident.id).toEqual(caseIncident.id);
    expect(editorQueryResult?.data?.caseIncident.currentUserAccessRight).toEqual('edit');
    expect(editorQueryResult?.data?.caseIncident.authorized_members.length).toEqual(0);
  });
  it('should Editor user edit case incident', async () => {
    const queryResult = await editorQuery({
      query: UPDATE_QUERY,
      variables: { id: caseIncident.id, input: { key: 'name', value: ['Case Incident Response - updated'] } },
    });
    expect(queryResult?.data?.stixDomainObjectEdit.fieldPatch.name).toEqual('Case Incident Response - updated');
    expect(queryResult?.data?.stixDomainObjectEdit.fieldPatch.currentUserAccessRight).toEqual('edit');
  });
  it('should Editor user not delete case incident with edit access right', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: DELETE_QUERY,
      variables: { id: caseIncident.id },
    });
  });
  it('should Admin user edit authorized members: Editor has admin access right', async () => {
    const caseIncidentResponseUpdatedQueryResult = await adminQuery({
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: {
        id: caseIncident.id,
        input: [
          {
            id: ADMIN_USER.id,
            access_right: 'admin'
          },
          {
            id: userEditorId,
            access_right: 'admin'
          }
        ]
      }
    });
    expect(caseIncidentResponseUpdatedQueryResult).not.toBeNull();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.currentUserAccessRight).toEqual('admin');
    expect(caseIncidentResponseUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).not.toBeUndefined();
    expect(caseIncidentResponseUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).toEqual([
      {
        member_id: ADMIN_USER.id,
        access_right: 'admin'
      },
      {
        member_id: userEditorId,
        access_right: 'admin'
      }
    ]);
  });
  it('should Editor user Case Incident Response deleted', async () => {
    // Delete the case
    await editorQuery({
      query: DELETE_QUERY,
      variables: { id: caseIncident.id },
    });
    // Verify is no longer found
    const queryResult = await adminQuery({ query: READ_QUERY, variables: { id: caseIncident.id } });
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
        name: authorizedMembers.name,
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
        member_id: ADMIN_USER.id,
        access_right: 'admin'
      }
    ]);
    caseIncidentResponseAuthorizedMembersFromSettings = caseIncidentResponseAuthorizedMembersData?.data?.caseIncidentAdd;
    // Clean
    const cleanAuthorizedMembersConfiguration = JSON.stringify([{ name: authorizedMembers.name, default_values: null }]);
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
  let organizationId: string;
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
    caseIrId = caseIRCreateQueryResult?.data?.caseIncidentAdd.id;
  });
  it('should EE activated', async () => {
    await enableEE();
  });
  it('should share Case Incident Response with Organization', async () => {
    // Get organization id
    organizationId = await getOrganizationIdByName(PLATFORM_ORGANIZATION.name);
    const organizationSharingQueryResult = await adminQuery({
      query: ORGANIZATION_SHARING_QUERY,
      variables: { id: caseIrId, organizationId }
    });
    expect(organizationSharingQueryResult).not.toBeNull();
    expect(organizationSharingQueryResult?.data?.stixCoreObjectEdit.restrictionOrganizationAdd).not.toBeNull();
    expect(organizationSharingQueryResult?.data?.stixCoreObjectEdit.restrictionOrganizationAdd.objectOrganization[0].name).toEqual(PLATFORM_ORGANIZATION.name);
  });
  it('should Editor user from different organization access Case Incident Response', async () => {
    const caseIRQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(caseIRQueryResult?.data?.caseIncident.id).toEqual(caseIrId);
  });
  it('should Security user from shared organization access Case Incident Response', async () => {
    const caseIRQueryResult = await securityQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(caseIRQueryResult?.data?.caseIncident.id).toEqual(caseIrId);
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
  it('should EE deactivated', async () => {
    await disableEE();
  });
});

describe('Case Incident Response and organization sharing standard behavior with platform organization', () => {
  let platformOrganizationId: string;
  let testOrganizationId: string;
  let caseIrId: string;
  let userEditorId: string;
  let settingsInternalId: string;
  it('should platform organization sharing and EE activated', async () => {
    // Get organization id
    platformOrganizationId = await getOrganizationIdByName(PLATFORM_ORGANIZATION.name);

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

    // Set platform organization
    const platformOrganization = await adminQueryWithSuccess({
      query: PLATFORM_ORGANIZATION_QUERY,
      variables: {
        id: settingsInternalId,
        input: [
          { key: 'platform_organization', value: platformOrganizationId },
          { key: 'enterprise_license', value: conf.get('app:enterprise_edition_license') },
        ]
      }
    });
    expect(platformOrganization?.data?.settingsEdit.fieldPatch.platform_organization).not.toBeUndefined();
    expect(platformOrganization?.data?.settingsEdit.fieldPatch.platform_enterprise_edition.license_validated).toBeTruthy();
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
    expect(caseIRCreateQueryResult?.data?.caseIncidentAdd).not.toBeUndefined();
    caseIrId = caseIRCreateQueryResult?.data?.caseIncidentAdd.id;
  });
  it('should Editor user not access Case Incident Response', async () => {
    const caseIRQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult.data?.caseIncident).toBeNull();
  });
  it('should Admin user activate Authorized Members', async () => {
    userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    const caseIRUpdatedQueryResult = await adminQuery({
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
    expect(caseIRUpdatedQueryResult).not.toBeNull();
    expect(caseIRUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).not.toBeUndefined();
    expect(caseIRUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).toEqual([
      {
        member_id: ADMIN_USER.id,
        access_right: 'admin'
      },
      {
        member_id: userEditorId,
        access_right: 'view'
      }
    ]);
  });
  it('should Editor user access Case Incident Response out of her organization if authorized members activated', async () => {
    const caseIRQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(caseIRQueryResult?.data?.caseIncident.id).toEqual(caseIrId);
    expect(caseIRQueryResult?.data?.caseIncident.currentUserAccessRight).toEqual('view');
  });
  it('user without bypass should not be allowed list all auth member restricted entities', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: LIST_RESTRICTED_ENTITIES,
      variables: { first: 10 }
    });
  });
  it('should BYPASS user be allowed list all auth member restricted entities', async () => {
    const queryResult = await adminQueryWithSuccess({ query: LIST_RESTRICTED_ENTITIES, variables: { first: 10 } });
    expect(queryResult?.data?.stixCoreObjectsRestricted.edges.length).toEqual(1);
  });
  it('should Admin user deactivate authorized members', async () => {
    await adminQuery({
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: {
        id: caseIrId,
        input: null,
      }
    });
    // Verify Editor user has no more access to Case incident
    const caseIRQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult.data?.caseIncident).toBeNull();
  });
  it('should share Case Incident Response with Organization', async () => {
    // Get organization id
    testOrganizationId = await getOrganizationIdByName(TEST_ORGANIZATION.name);
    const organizationSharingQueryResult = await adminQuery({
      query: ORGANIZATION_SHARING_QUERY,
      variables: { id: caseIrId, organizationId: testOrganizationId }
    });
    expect(organizationSharingQueryResult).not.toBeNull();
    expect(organizationSharingQueryResult?.data?.stixCoreObjectEdit.restrictionOrganizationAdd).not.toBeNull();
    expect(organizationSharingQueryResult?.data?.stixCoreObjectEdit.restrictionOrganizationAdd.objectOrganization[0].name).toEqual(TEST_ORGANIZATION.name);

    // Verify Editor user has access to Case incident
    const caseIRQueryResult = await editorQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(caseIRQueryResult).not.toBeNull();
    expect(caseIRQueryResult?.data?.caseIncident).not.toBeUndefined();
    expect(caseIRQueryResult?.data?.caseIncident.id).toEqual(caseIrId);
  });
  it('should platform organization sharing and EE deactivated', async () => {
    // Remove platform organization
    const platformOrganization = await adminQueryWithSuccess({
      query: PLATFORM_ORGANIZATION_QUERY,
      variables: {
        id: settingsInternalId,
        input: [
          { key: 'platform_organization', value: [] },
          { key: 'enterprise_license', value: [] },
        ]
      }
    });
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

describe('Restricted entities listing', () => {
  let caseIrId: string;
  let userEditorId: string;
  let reportId: string;
  it('should platform organization sharing and EE activated', async () => {
    await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);
  });
  it('should Case Incident Response created', async () => {
    // Create Case Incident Response
    const caseIRCreateQueryResult = await adminQueryWithSuccess({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Case IR with platform orga'
        }
      }
    });
    expect(caseIRCreateQueryResult?.data?.caseIncidentAdd).not.toBeUndefined();
    caseIrId = caseIRCreateQueryResult?.data?.caseIncidentAdd.id;
  }); // +1 create
  it('should Admin user activate Authorized Members for Case IR', async () => { // +1 update
    userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    const caseIRUpdatedQueryResult = await adminQuery({
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
    expect(caseIRUpdatedQueryResult).not.toBeNull();
    expect(caseIRUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).not.toBeUndefined();
    expect(caseIRUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).toEqual([
      {
        member_id: ADMIN_USER.id,
        access_right: 'admin'
      },
      {
        member_id: userEditorId,
        access_right: 'view'
      }
    ]);
  });
  it('should Report created', async () => { // +1 create
    // Create Report
    const reportCreateQueryResult = await adminQueryWithSuccess({
      query: CREATE_REPORT_QUERY,
      variables: {
        input: {
          name: 'Report name',
          published: '2023-06-01T22:00:00.000Z',
        }
      }
    });
    expect(reportCreateQueryResult?.data?.reportAdd).not.toBeUndefined();
    reportId = reportCreateQueryResult?.data?.reportAdd.id;
  });
  it('should Admin user activate Authorized Members for Report', async () => {
    userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    const reportUpdatedQueryResult = await adminQueryWithSuccess({
      query: EDIT_AUTHORIZED_MEMBERS_QUERY,
      variables: {
        id: reportId,
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
    expect(reportUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).not.toBeUndefined();
    expect(reportUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members).toEqual([
      {
        member_id: ADMIN_USER.id,
        access_right: 'admin'
      },
      {
        member_id: userEditorId,
        access_right: 'view'
      }
    ]);
    expect(reportUpdatedQueryResult?.data?.containerEdit.editAuthorizedMembers.authorized_members_activation_date).toBeDefined();
  }); // +1 update
  it('using platform org - user without bypass should not be allowed list all auth member restricted entities', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: LIST_RESTRICTED_ENTITIES,
      variables: { first: 10 }
    });
  });
  it('using platform org - should BYPASS user be allowed list all auth member restricted entities', async () => {
    const queryResult = await adminQueryWithSuccess({ query: LIST_RESTRICTED_ENTITIES, variables: { first: 10 } });
    expect(queryResult?.data?.stixCoreObjectsRestricted.edges.length).toEqual(2);
  });
  it('should platform organization sharing and EE deactivated', async () => {
    await enableCEAndUnSetOrganization();
  });
  it('should Case Incident Response deleted', async () => {
    // Delete the case
    await adminQuery({
      query: DELETE_QUERY,
      variables: { id: caseIrId },
    });
    // Verify that it is no longer found
    const queryResult = await adminQuery({ query: READ_QUERY, variables: { id: caseIrId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).toBeNull();
  }); // +1 delete
  it('should Report deleted', async () => {
    // Delete the case
    await adminQuery({
      query: DELETE_REPORT_QUERY,
      variables: { id: reportId },
    });
    // Verify is no longer found
    const queryResult = await adminQueryWithSuccess({ query: READ_REPORT_QUERY, variables: { id: reportId } });
    expect(queryResult?.data?.report).toBeNull();
  }); // +1 delete
});
