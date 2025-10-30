import { createInferredEntity, createInferredRelation } from '../database/middleware';
import type { AuthContext, AuthUser } from '../types/user';
import { RULE_MANAGER_USER } from '../utils/access';
import { ForbiddenAccess } from '../config/errors';
import { publishStixToStream } from '../database/redis';

export const createInternalInferredRelation = async (context: AuthContext, user: AuthUser, jsonInput: string) => {
  // This API should only be available to task manager user
  if (user.id !== RULE_MANAGER_USER.id) {
    throw ForbiddenAccess();
  }
  // TODO: JSON input validation? Maybe we don't need it since it's only coming from task manager?
  const { input, ruleContent, opts } = JSON.parse(jsonInput);
  // Handle special case of inferred rel creation used to push event to stream
  if (opts?.isPublishStixToStream) {
    const event = opts.publishStixEvent;
    await publishStixToStream(context, RULE_MANAGER_USER, event);
    return null;
  }
  const createdInferredRelation = await createInferredRelation(context, input, ruleContent, opts);
  return createdInferredRelation.id;
};
export const createInternalInferredEntity = async (context: AuthContext, user: AuthUser, jsonInput: string) => {
  // This API should only be available to task manager user
  if (user.id !== RULE_MANAGER_USER.id) {
    throw ForbiddenAccess();
  }
  // TODO: JSON input validation? Maybe we don't need it since it's only coming from task manager?
  const { input, ruleContent, type } = JSON.parse(jsonInput);
  const createdInferredEntity = await createInferredEntity(context, input, ruleContent, type);
  return createdInferredEntity.id;
};
