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
import { createInternalObject } from '../../domain/internalObject';
import { ENTITY_TYPE_REQUEST_ACCESS_FLOW, type StoreEntityRequestAccessFlow } from './requestAccessFlow-types';

export interface RequestAccessAction {
  reason?: string
  entities?: string[]
  members?: string[]
  type?: string,
  status: string,
  executionDate?: Date
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

export const generateBasicFlow = async (context: AuthContext, user: AuthUser) => {
  const toNew = {
    from: ActionStatus.New,
    to: ActionStatus.New
  };
  await createInternalObject<StoreEntityRequestAccessFlow>(context, user, toNew, ENTITY_TYPE_REQUEST_ACCESS_FLOW);

  const fromNewToAccepted = {
    from: ActionStatus.New,
    to: ActionStatus.Accepted
  };
  await createInternalObject<StoreEntityRequestAccessFlow>(context, user, fromNewToAccepted, ENTITY_TYPE_REQUEST_ACCESS_FLOW);

  const fromNewToRefused = {
    from: ActionStatus.New,
    to: ActionStatus.Refused
  };
  await createInternalObject<StoreEntityRequestAccessFlow>(context, user, fromNewToRefused, ENTITY_TYPE_REQUEST_ACCESS_FLOW);

  const fromRefusedToANew = {
    from: ActionStatus.Refused,
    to: ActionStatus.New
  };
  await createInternalObject<StoreEntityRequestAccessFlow>(context, user, fromRefusedToANew, ENTITY_TYPE_REQUEST_ACCESS_FLOW);
};

export const getRFIStatusOnApprove = () => {
  // "key": "x_opencti_workflow_id",
  //     "value": "cc6ae8d3-401c-4e25-b2c6-276680233930"
  // FIXME works only on my computer :D
  return 'a83e3917-2d09-49fa-83cc-608f37466118';
};

export const getRFIStatusOnReject = () => {
  // "key": "x_opencti_workflow_id",
  //     "value": "cc6ae8d3-401c-4e25-b2c6-276680233930"
  // FIXME works only on my computer :D
  return '217319ad-60b3-44b3-abf6-34e1c055d686';
};

export const getRFIStatusOnReopen = () => {
  // "key": "x_opencti_workflow_id",
  //     "value": "cc6ae8d3-401c-4e25-b2c6-276680233930"
  // FIXME works only on my computer :D
  return '6bf11b7c-cb6c-4751-90b7-b6e09ebf98d5';
};

export const addRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessAddInput) => {
  logApp.info('[OPENCTI-MODULE][Request access] - addRequestAccess', { input });
  const allAssignees = await findUsersThatCanShareWithOrganizations(context, SYSTEM_USER, input.request_access_members);
  const allAssigneeIds: string[] = allAssignees.map((member) => member.id);
  if (allAssigneeIds.length < 1) {
    logApp.warn('[OPENCTI-MODULE][Request access] Cannot set Assignee in Request Access RFI', { input });
  }
  const requestedEntities = input.request_access_entities;

  const action: RequestAccessAction = {
    reason: input.request_access_reason || 'no reason',
    members: input.request_access_members,
    type: input.request_access_type?.toString(),
    entities: input.request_access_entities,
    status: ActionStatus.New,
  };

  const organizationId = input.request_access_members[0];
  const elementId = input.request_access_entities[0];

  const elementData = await elLoadById(context, SYSTEM_USER, elementId) as unknown as BasicStoreBase;
  const mainRepresentative = extractEntityRepresentativeName(elementData);
  const organizationData = await findOrganizationById(context, SYSTEM_USER, organizationId);
  const humanDescription = `Access requested:\n - by user: ${user.name} \n - for organization: ${organizationData.name} \n - for ${elementData.entity_type} ${mainRepresentative} ${elementData.id}`;

  const rfiInput: CaseRfiAddInput = {
    name: `Request Access for entity ${mainRepresentative} by ${user.name} via organization ${organizationData.name}`,
    objectParticipant: [user.id],
    objects: requestedEntities,
    objectAssignee: allAssigneeIds,
    description: humanDescription,
    information_types: ['Request sharing'],
    x_opencti_request_access: `${JSON.stringify(action)}`
  };
  logApp.info('[OPENCTI-MODULE][Request access] - rfiInput', { rfiInput });
  const requestForInformation = await addCaseRfi(context, SYSTEM_USER, rfiInput);
  return requestForInformation.id;
};

export const validateRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info(`'[OPENCTI-MODULE][Request access] 1 - Validation for RFI ${id}`);
  const rfi = await findRFIById(context, user, id);
  logApp.info(`'[OPENCTI-MODULE][Request access] 2 -Validation for RFI ${id}`, { rfiFound: rfi });
  if (rfi.x_opencti_request_access) {
    const actionData = rfi.x_opencti_request_access;
    logApp.info('[OPENCTI-MODULE][Request access] 3 Action data', { actionData });
    const action: RequestAccessAction = JSON.parse(actionData);
    logApp.info(`'[OPENCTI-MODULE][Request access] 4 Action parsed on RFI ${id}`, action);

    if (action.status === ActionStatus.New) {
      if (action.entities && action.members) {
        await addOrganizationRestriction(context, user, action.entities[0], action.members[0]);

        // Moving RFI to approved
        const requestAccessAction: RequestAccessAction = { ...action, status: ActionStatus.Accepted, executionDate: new Date() };
        const RFIFieldPatch :EditInput[] = [
          { key: 'x_opencti_request_access', value: [`${JSON.stringify(requestAccessAction)}`] },
          { key: 'x_opencti_workflow_id', value: [getRFIStatusOnApprove()] }
        ];
        await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);
        return {
          action_executed: true,
          action_status: ActionStatus.Accepted,
          action_date: requestAccessAction.executionDate
        };
      }
      logApp.error('Request Access is missing entities or members', { action, RFIId: id });
      return {
        action_executed: false,
        action_status: ActionStatus.MissingParameters,
      };
    }
    logApp.info('Request Access already accepted or refused', { action, RFIId: id });
    return {
      action_executed: false,
      action_status: action.status,
      action_date: action.executionDate
    };
  }
  logApp.error('RFI not found for Request Access', { RFIId: id });
  return {
    action_executed: false,
    action_status: ActionStatus.NotFound,
  };
};

export const rejectRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info(`Reject for RFI ${id}`);

  const rfi = await findRFIById(context, user, id);
  const actionData = rfi.x_opencti_request_access;
  const action: RequestAccessAction = JSON.parse(actionData);
  logApp.info(`Action on RFI ${id}`, action);

  if (action.status === ActionStatus.New) {
    if (action.entities && action.members) {
      // Burning RFI
      const requestAccessAction: RequestAccessAction = { ...action, status: ActionStatus.Refused, executionDate: new Date() };
      const RFIFieldPatch :EditInput[] = [
        { key: 'x_opencti_request_access', value: [`${JSON.stringify(requestAccessAction)}`] },
        { key: 'x_opencti_workflow_id', value: [getRFIStatusOnReject()] }
      ];
      await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);
      return {
        action_executed: true,
        action_status: ActionStatus.Refused,
        action_date: requestAccessAction.executionDate
      };
    }
    logApp.error('Request Access is missing entities or members', { action, RFIId: id });
    return {
      action_executed: false,
      action_status: ActionStatus.MissingParameters,
    };
  }
  logApp.info('Request Access already accepted or refused', { action, RFIId: id });
  return {
    action_executed: false,
    action_status: action.status,
    action_date: action.executionDate
  };
};

export const reopenRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info(`Reopen for RFI ${id}`);

  const rfi = await findRFIById(context, user, id);
  const actionData = rfi.x_opencti_request_access;
  const action: RequestAccessAction = JSON.parse(actionData);
  logApp.info(`Action on RFI ${id}`, action);

  if (action.status === ActionStatus.Refused) {
    if (action.entities && action.members) {
      // Reopening RFI
      const requestAccessAction: RequestAccessAction = { ...action, status: ActionStatus.New, executionDate: new Date() };
      const RFIFieldPatch :EditInput[] = [
        { key: 'x_opencti_request_access', value: [`${JSON.stringify(requestAccessAction)}`] },
        { key: 'x_opencti_workflow_id', value: [getRFIStatusOnReopen()] }
      ];
      await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);
      return {
        action_executed: true,
        action_status: ActionStatus.New,
        action_date: requestAccessAction.executionDate
      };
    }
    logApp.error('Request Access is missing entities or members', { action, RFIId: id });
    return {
      action_executed: false,
      action_status: ActionStatus.MissingParameters,
    };
  }
  return {
    action_executed: false,
    action_status: action.status,
    action_date: action.executionDate
  };
};
