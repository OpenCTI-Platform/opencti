import type { AuthContext, AuthUser } from '../../types/user';
import type { CaseRfiAddInput, RequestAccessAddInput } from '../../generated/graphql';
import { addCaseRfi } from '../case/case-rfi/case-rfi-domain';
import { isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT } from '../../utils/access';
import { listAllFromEntitiesThroughRelations } from '../../database/middleware-loader';
import { RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { findById as findUserById } from '../../domain/user';
import { logApp } from '../../config/conf';

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
  logApp.warn('ANGIE - addRequestAccess', { input });
  const allAssignees = await findUsersThatCanShareWithOrganizations(context, user, input.request_access_members);
  const allAssigneeIds: string[] = allAssignees.map((member) => member.id);
  if (allAssigneeIds.length) {
    logApp.warn('[OPENCTI-MODULE] Cannot set Assignee in Request Access RFI', { input });
  }
  const requestedEntities = input.request_access_entities;

  const rfiInput: CaseRfiAddInput = {
    name: `Request Access for entity ${input.request_access_entities.join(', ')}`,
    objectParticipant: [user.id],
    objects: requestedEntities,
    objectAssignee: allAssigneeIds,
    description: `Access requested by ${user.user_email} to organization ${JSON.stringify(input.request_access_members)} for ${JSON.stringify(requestedEntities)}`
  };
  const requestForInformation = await addCaseRfi(context, user, rfiInput);
  return requestForInformation.id;
};

/*
export const validateRequestAccess = (context: AuthContext, user: AuthUser, id: string) => {
  // TODO: return the validation of request
  return true;
};

 */
