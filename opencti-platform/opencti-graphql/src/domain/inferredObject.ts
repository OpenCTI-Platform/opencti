import { createInferredEntity, createInferredRelation } from '../database/middleware';
import type { AuthContext, AuthUser } from '../types/user';
import { RULE_MANAGER_USER } from '../utils/access';
import { ForbiddenAccess } from '../config/errors';

export const createInternalInferredRelation = async (context: AuthContext, user: AuthUser, jsonInput: string) => {
  // This API should only be available to task manager user
  if (user.id !== RULE_MANAGER_USER.id) {
    throw ForbiddenAccess();
  }
  const { input, ruleContent, opts } = JSON.parse(jsonInput);
  const createdInferredRelation = await createInferredRelation(context, input, ruleContent, opts);
  return createdInferredRelation.id;
};
export const createInternalInferredEntity = async (context: AuthContext, user: AuthUser, jsonInput: string) => {
  // This API should only be available to task manager user
  if (user.id !== RULE_MANAGER_USER.id) {
    throw ForbiddenAccess();
  }
  const { input, ruleContent, type } = JSON.parse(jsonInput);
  const createdInferredEntity = await createInferredEntity(context, input, ruleContent, type);
  return createdInferredEntity.id;
};
