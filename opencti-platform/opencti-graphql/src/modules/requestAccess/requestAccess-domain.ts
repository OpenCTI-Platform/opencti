import type { AuthContext, AuthUser } from '../../types/user';
import type { CaseRfiAddInput, RequestAccessAddInput } from '../../generated/graphql';
import { addCaseRfi } from '../case/case-rfi/case-rfi-domain';
import { isUserCanAccessStoreElement } from '../../utils/access';
import { storeLoadById } from '../../database/middleware-loader';
import type { BasicStoreCommon } from '../../types/store';

export const addRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessAddInput) => {
  // TODO: find assignee
  const requestedEntities = input.request_access_entities;
  const assigneeId = await Promise.all(
    requestedEntities.map(async (entityId) => {
      try {
        const requestedEntity = await storeLoadById<BasicStoreCommon>(context, user, entityId, 'StixObject');
        const canAccess = await isUserCanAccessStoreElement(context, user, requestedEntity);
        return canAccess ? requestedEntity.internal_id : null;
      } catch {
        return null;
      }
    })
  ).then((results) => results.find((id) => id !== null));

  const rfiInput: CaseRfiAddInput = {
    name: `Request Access for entity ${input.request_access_entities.join(', ')}`,
    objectParticipant: [user.id],
    objects: input.request_access_entities,
    objectAssignee: assigneeId ? [assigneeId] : [],
  };
  const requestForInformation = await addCaseRfi(context, user, rfiInput);
  return requestForInformation.id;
};

export const validateRequestAccess = (context: AuthContext, user: AuthUser, id: string) => {
  // TODO: return the validation of request
  return true;
};
