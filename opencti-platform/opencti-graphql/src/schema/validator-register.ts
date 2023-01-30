import type { AuthContext, AuthUser } from '../types/user';

export type ValidatorFn = (context: AuthContext, user: AuthUser, instance: Record<string, unknown>, initialInstance?: Record<string, unknown>) => Promise<boolean>;

const entityValidators = new Map<string, { validatorCreation?: ValidatorFn, validatorUpdate?: ValidatorFn }>();
export const registerEntityValidator = (type: string, validators: { validatorCreation?: ValidatorFn, validatorUpdate?: ValidatorFn }) => {
  entityValidators.set(type, validators);
};
export const getEntityValidatorCreation = (type: string): ValidatorFn | undefined => {
  return entityValidators.get(type)?.validatorCreation;
};
export const getEntityValidatorUpdate = (type: string):ValidatorFn | undefined => {
  return entityValidators.get(type)?.validatorUpdate;
};
