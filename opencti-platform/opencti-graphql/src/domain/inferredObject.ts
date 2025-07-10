import { createInferredEntity, createInferredRelation } from '../database/middleware';
import type { AuthContext, AuthUser } from '../types/user';

export const createInternalInferredRelation = async (context: AuthContext, _user: AuthUser, jsonInput: string) => {
  const { input, ruleContent, opts } = JSON.parse(jsonInput);
  const createdInferredRelation = await createInferredRelation(context, input, ruleContent, opts);
  return createdInferredRelation.id;
};
export const createInternalInferredEntity = async (context: AuthContext, _user: AuthUser, jsonInput: string) => {
  const { input, ruleContent, type } = JSON.parse(jsonInput);
  const createdInferredRelation = await createInferredEntity(context, input, ruleContent, type);
  return createdInferredRelation.id;
};
