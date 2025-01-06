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
    status: ActionStatus.NotDone,
  };

  const rfiInput: CaseRfiAddInput = {
    name: `Request Access by ${user.user_email} for entity ${input.request_access_entities.join(', ')} to organization ${JSON.stringify(input.request_access_members)}`,
    objectParticipant: [user.id],
    objects: requestedEntities,
    objectAssignee: allAssigneeIds,
    description: `${JSON.stringify(action)}`
  };
  logApp.info('[OPENCTI-MODULE][Request access] - rfiInput', { rfiInput });
  const requestForInformation = await addCaseRfi(context, SYSTEM_USER, rfiInput);
  return requestForInformation.id;
};

export const validateRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info(`'[OPENCTI-MODULE][Request access] 1 - Validation for RFI ${id}`);
  const rfi = await findRFIById(context, user, id);
  logApp.info(`'[OPENCTI-MODULE][Request access] 2 -Validation for RFI ${id}`, { rfiFound: rfi });
  if (rfi.description) {
    // Get data in description for now, will be somewhere else at the end.
    const actionData = rfi.description;
    logApp.info('[OPENCTI-MODULE][Request access] 3 Action data', { actionData });
    const action: RequestAccessAction = JSON.parse(actionData);
    logApp.info(`'[OPENCTI-MODULE][Request access] 4 Action parsed on RFI ${id}`, action);

    if (action.status === ActionStatus.NotDone) {
      if (action.entities && action.members) {
        await addOrganizationRestriction(context, user, action.entities[0], action.members[0]);

        // Burning RFI
        const burnedAction: RequestAccessAction = { ...action, status: ActionStatus.Accepted, executionDate: new Date() };
        const RFIFieldPatch :EditInput[] = [{ key: 'description', value: [`${JSON.stringify(burnedAction)}`] }];
        await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);
        return {
          action_executed: true,
          action_status: ActionStatus.Accepted,
          action_date: burnedAction.executionDate
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
  // Get data in description for now, will be somewhere else at the end.
  const actionData = rfi.description;
  const action: RequestAccessAction = JSON.parse(actionData);
  logApp.info(`Action on RFI ${id}`, action);

  if (action.status === ActionStatus.NotDone) {
    if (action.entities && action.members) {
      // Burning RFI
      const burnedAction: RequestAccessAction = { ...action, status: ActionStatus.Refused, executionDate: new Date() };
      const RFIFieldPatch :EditInput[] = [{ key: 'description', value: [`${JSON.stringify(burnedAction)}`] }];
      await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);
      return {
        action_executed: true,
        action_status: ActionStatus.Refused,
        action_date: burnedAction.executionDate
      };
    }
    logApp.error('Request Access is missing entities or members', { action, RFIId: id });
    return {
      action_executed: true,
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
