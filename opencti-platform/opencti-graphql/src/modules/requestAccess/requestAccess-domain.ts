import type { AuthContext, AuthUser } from '../../types/user';
import type { CaseRfiAddInput, RequestAccessAddInput } from '../../generated/graphql';
import { addCaseRfi } from '../case/case-rfi/case-rfi-domain';

export const addRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessAddInput) => {
  // TODO: find assignee
  const rfiInput: CaseRfiAddInput = {
    name: `Request Access for entity ${input.request_access_entities.join(', ')}`,
    objectParticipant: [user.id],
    objects: input.request_access_entities,
  };
  const requestForInformation = await addCaseRfi(context, user, rfiInput);
  return requestForInformation.id;
};

export const validateRequestAccess = (context: AuthContext, user: AuthUser, id: string) => {
  // TODO: return the validation of request
  return true;
};
