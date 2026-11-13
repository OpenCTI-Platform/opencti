import type { AuthContext, AuthUser } from '../types/user';

export type ValidatorFn = (context: AuthContext, user: AuthUser, instance: Record<string, unknown>, initialInstance?: Record<string, unknown>) => Promise<boolean>;

const entityValidators = new Map<string, { validatorCreation?: ValidatorFn; validatorUpdate?: ValidatorFn }>();
// Several modules can validate the same type: the input is valid when every validator registered for it accepts it
const allOf = (registered?: ValidatorFn, added?: ValidatorFn): ValidatorFn | undefined => {
  if (!registered || !added) {
    return registered ?? added;
  }
  return async (...args) => (await registered(...args)) && (await added(...args));
};
export const registerEntityValidator = (type: string, validators: { validatorCreation?: ValidatorFn; validatorUpdate?: ValidatorFn }) => {
  const registered = entityValidators.get(type);
  entityValidators.set(type, {
    validatorCreation: allOf(registered?.validatorCreation, validators.validatorCreation),
    validatorUpdate: allOf(registered?.validatorUpdate, validators.validatorUpdate),
  });
};
export const getEntityValidatorCreation = (type: string): ValidatorFn | undefined => {
  return entityValidators.get(type)?.validatorCreation;
};
export const getEntityValidatorUpdate = (type: string): ValidatorFn | undefined => {
  return entityValidators.get(type)?.validatorUpdate;
};
