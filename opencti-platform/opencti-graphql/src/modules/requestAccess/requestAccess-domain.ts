import type { AuthContext, AuthUser } from '../../types/user';
import { ActionStatus, type CaseRfiAddInput, type EditInput, type RequestAccessAddInput } from '../../generated/graphql';
import { addCaseRfi, findById as findRFIById } from '../case/case-rfi/case-rfi-domain';
import { isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT, SYSTEM_USER } from '../../utils/access';
import { listAllFromEntitiesThroughRelations } from '../../database/middleware-loader';
import { RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { findById as findUserById } from '../../domain/user';
import { logApp } from '../../config/conf';
import { addOrganizationRestriction } from '../../domain/stix';
import { updateAttribute } from '../../database/middleware';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { findById as findOrganizationById } from '../organization/organization-domain';
import { elLoadById } from '../../database/engine';
import type { BasicStoreBase } from '../../types/store';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { findByType as findEntitySettingsByType } from '../entitySetting/entitySetting-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';
import { batchStatusesByType } from '../../domain/status';

export interface RequestAccessActionStatus {
  rfiStatusId: string,
  actionStatus: ActionStatus
}

export interface RequestAccessAction {
  reason?: string
  entities?: string[]
  members?: string[]
  type?: string,
  status: string,
  executionDate?: Date,
  workflowMapping: RequestAccessActionStatus[]
}

export const findUsersThatCanShareWithOrganizations = async (context: AuthContext, user: AuthUser, organizationIds: string[]) => {
  const allUserInOrgWithOrgManagementCapability = [];
  for (let orgI = 0; orgI < organizationIds.length; orgI += 1) {
    const organizationId = organizationIds[orgI];
    const allUserInOrg = await listAllFromEntitiesThroughRelations(context, user, organizationId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_USER);
    for (let userI = 0; userI < allUserInOrg.length; userI += 1) {
      const authUserFromUserId = await findUserById(context, user, allUserInOrg[userI].id);
      if (isUserHasCapability(authUserFromUserId, KNOWLEDGE_ORGANIZATION_RESTRICT)) {
        allUserInOrgWithOrgManagementCapability.push(authUserFromUserId);
      }
    }
  }
  return allUserInOrgWithOrgManagementCapability;
};

/*
interface RequestAccessWorkflowSettings {
  workflow: string[]
  approved_workflow_id: string,
  declined_workflow_id: string
} */

export const getRFIStatusForAction = async (context: AuthContext, user: AuthUser, action:ActionStatus) => {
  const rfiEntitySettings = await findEntitySettingsByType(context, user, ENTITY_TYPE_CONTAINER_CASE_RFI);
  const requestAccessWorkflow = rfiEntitySettings.request_access_workflow;
  if (requestAccessWorkflow) {
    if (action === ActionStatus.Approved) {
      return requestAccessWorkflow.approved_workflow_id;
    }

    if (action === ActionStatus.Declined) {
      return requestAccessWorkflow.declined_workflow_id;
    }
  }
  return undefined;
};

export const getRFIStatusMap = async (context: AuthContext, user: AuthUser) => {
  const rfiEntitySettings = await findEntitySettingsByType(context, user, ENTITY_TYPE_CONTAINER_CASE_RFI);
  const requestAccessWorkflow = rfiEntitySettings.request_access_workflow;
  const result : RequestAccessActionStatus[] = [];
  if (requestAccessWorkflow) {
    if (requestAccessWorkflow.approved_workflow_id) {
      result.push({
        rfiStatusId: requestAccessWorkflow.approved_workflow_id,
        actionStatus: ActionStatus.Approved,
      });
    }

    if (requestAccessWorkflow.declined_workflow_id) {
      result.push({
        rfiStatusId: requestAccessWorkflow.declined_workflow_id,
        actionStatus: ActionStatus.Declined,
      });
    }
  }
  // const workflowConfig = rfiEntitySettings.workflow_configuration;
  const allWorkflowStatus = await batchStatusesByType(context, user, [ENTITY_TYPE_CONTAINER_CASE_RFI]);
  console.log('ANGIE allWorkflowStatus', allWorkflowStatus);

  result.push({
    rfiStatusId: 'TODO',
    actionStatus: ActionStatus.New });
  return result;
};

const computeAuthorizedMembersForRequestAccess = (grantedOrganizationsIds) => {
  const authorizedMembers = [];
  // TODO get admin orga from request access entity settings
  if (grantedOrganizationsIds.length < 1) {
    authorizedMembers.push({
      id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      access_right: 'admin',
    });
  }
  if (grantedOrganizationsIds.length < 1) {
    // Todo: if no granted ref => use main platform orga
  }
  if (grantedOrganizationsIds.length > 0) {
    grantedOrganizationsIds.map((organizationId) => authorizedMembers.push({
      id: organizationId,
      access_right: 'edit',
    }));
  }
  return authorizedMembers;
};

export const addRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessAddInput) => {
  logApp.info('[OPENCTI-MODULE][Request access] - addRequestAccess', { input });

  // FIXME move that away
  // await generateInitialFlow(context, user);

  const allUsers = await findUsersThatCanShareWithOrganizations(context, SYSTEM_USER, input.request_access_members); // TODO modifify findUsersThatCanShareWithOrganizations
  const grantedOrganizationsIds: string[] = allUsers.map((user) => user.organizations); // TODO fix this
  const authorized_members = computeAuthorizedMembersForRequestAccess(grantedOrganizationsIds);

  const requestedEntities = input.request_access_entities;
  const allActionStatuses = await getRFIStatusMap(context, user);

  const action: RequestAccessAction = {
    reason: input.request_access_reason || 'no reason',
    members: input.request_access_members,
    type: input.request_access_type?.toString(),
    entities: input.request_access_entities,
    status: ActionStatus.New, // TODO set workflow status id instead
    workflowMapping: allActionStatuses
  };

  const organizationId = input.request_access_members[0];
  const elementId = input.request_access_entities[0];

  const elementData = await elLoadById(context, SYSTEM_USER, elementId) as unknown as BasicStoreBase;
  const mainRepresentative = extractEntityRepresentativeName(elementData);
  const organizationData = await findOrganizationById(context, SYSTEM_USER, organizationId);
  const humanDescription = `Access requested:\n - by user: ${user.name} \n - for organization: ${organizationData.name} \n - for ${elementData.entity_type} ${mainRepresentative} ${elementData.id}`;

  const x_opencti_workflow_id = await getRFIStatusForAction(context, user, ActionStatus.New);
  const rfiInput: CaseRfiAddInput = {
    name: `Request Access for entity ${mainRepresentative} by ${user.name} via organization ${organizationData.name}`,
    objectParticipant: [user.id],
    objects: requestedEntities,
    description: humanDescription,
    information_types: ['Request sharing'],
    x_opencti_request_access: `${JSON.stringify(action)}`,
    authorized_members,
    x_opencti_workflow_id
  };
  logApp.info('[OPENCTI-MODULE][Request access] - rfiInput', { rfiInput });
  const requestForInformation = await addCaseRfi(context, SYSTEM_USER, rfiInput);
  return requestForInformation.id;
};

export const approveRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info(`'[OPENCTI-MODULE][Request access] 1 - Validation for RFI ${id}`);
  const rfi = await findRFIById(context, user, id);
  logApp.info(`'[OPENCTI-MODULE][Request access] 2 -Validation for RFI ${id}`, { rfiFound: rfi });
  if (rfi.x_opencti_request_access) {
    const actionData = rfi.x_opencti_request_access;
    logApp.info('[OPENCTI-MODULE][Request access] 3 Action data', { actionData });
    const action: RequestAccessAction = JSON.parse(actionData);
    logApp.info(`'[OPENCTI-MODULE][Request access] 4 Action parsed on RFI ${id}`, action);

    if (action.entities && action.members) {
      await addOrganizationRestriction(context, user, action.entities[0], action.members[0]);

      const x_opencti_workflow_id = await getRFIStatusForAction(context, user, ActionStatus.Approved);
      const allActionStatuses = await getRFIStatusMap(context, user);
      // Moving RFI to approved
      const requestAccessAction: RequestAccessAction = {
        ...action,
        status: ActionStatus.Approved,
        executionDate: new Date(),
        workflowMapping: allActionStatuses
      };
      const RFIFieldPatch :EditInput[] = [
        { key: 'x_opencti_request_access', value: [`${JSON.stringify(requestAccessAction)}`] },
      ];

      if (x_opencti_workflow_id) {
        RFIFieldPatch.push({ key: 'x_opencti_workflow_id', value: [x_opencti_workflow_id] });
      }
      await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);

      /*
        const elementData = await stixLoadById(context, SYSTEM_USER, action.entities[0]) as StixObject;
        const userToNotify : NotificationUser = {
          user_id: '',
          user_email: 'angelique.jard@filigran.io',
          notifiers: []
        };
        const target = {
          user: userToNotify,
          type: 'live',
          message: 'Coucou'
        };
        const notificationEvent: KnowledgeNotificationEvent = {
          origin: undefined,
          type: 'live',
          notification_id: '1234',
          data: elementData,
          targets: [target],
          version: '1.0' };
        await storeNotificationEvent(context, notificationEvent);
        */
      return {
        action_executed: true,
        action_status: ActionStatus.Approved, // TODO set workflow status id instead
        action_date: requestAccessAction.executionDate
      };
    }
    logApp.error('Request Access is missing entities or members', { action, RFIId: id });
    return {
      action_executed: false,
      action_status: ActionStatus.MissingParameters,
    };
  }
  logApp.error('RFI not found for Request Access', { RFIId: id });
  return {
    action_executed: false,
    action_status: ActionStatus.NotFound,
  };
};

export const declineRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info(`Reject for RFI ${id}`);

  const rfi = await findRFIById(context, user, id);
  const actionData = rfi.x_opencti_request_access;
  const action: RequestAccessAction = JSON.parse(actionData);
  logApp.info(`Action on RFI ${id}`, action);

  if (action.entities && action.members) {
    const x_opencti_workflow_id = await getRFIStatusForAction(context, user, ActionStatus.Declined);
    const allActionStatuses = await getRFIStatusMap(context, user);
    const requestAccessAction: RequestAccessAction = {
      ...action,
      status: ActionStatus.Declined,
      executionDate: new Date(),
      workflowMapping: allActionStatuses
    };
    const RFIFieldPatch :EditInput[] = [
      { key: 'x_opencti_request_access', value: [`${JSON.stringify(requestAccessAction)}`] }
    ];

    if (x_opencti_workflow_id) {
      RFIFieldPatch.push({ key: 'x_opencti_workflow_id', value: [x_opencti_workflow_id] });
    }
    await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);
    return {
      action_executed: true,
      action_status: ActionStatus.Declined,
      action_date: requestAccessAction.executionDate
    };
  }
  logApp.error('Request Access is missing entities or members', { action, RFIId: id });
  return {
    action_executed: false,
    action_status: ActionStatus.MissingParameters,
  };
};
