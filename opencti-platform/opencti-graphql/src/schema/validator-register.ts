import type { AuthContext, AuthUser } from '../types/user';

export type ValidatorFn = (context: AuthContext, user: AuthUser, instance: Record<string, unknown>, instanceId: string | undefined) => Promise<boolean>;

const entityValidators = new Map<string, ValidatorFn>();
export const registerEntityValidator = (type: string, validatorFn: ValidatorFn) => {
  entityValidators.set(type, validatorFn);
};
export const getEntityValidator = (type: string):ValidatorFn | undefined => {
  return entityValidators.get(type);
};
