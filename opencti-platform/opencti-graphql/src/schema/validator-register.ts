import type { AuthContext, AuthUser } from '../types/user';
import type { EditInput } from '../generated/graphql';

// On update, `instance` holds the edited values by key and `editInputs` the edits themselves, with their operation.
export type ValidatorFn = (
  context: AuthContext,
  user: AuthUser,
  instance: Record<string, unknown>,
  initialInstance?: Record<string, unknown>,
  editInputs?: EditInput[],
) => Promise<boolean>;

const entityValidators = new Map<string, { validatorCreation?: ValidatorFn; validatorUpdate?: ValidatorFn }>();
export const registerEntityValidator = (type: string, validators: { validatorCreation?: ValidatorFn; validatorUpdate?: ValidatorFn }) => {
  entityValidators.set(type, validators);
};
export const getEntityValidatorCreation = (type: string): ValidatorFn | undefined => {
  return entityValidators.get(type)?.validatorCreation;
};
export const getEntityValidatorUpdate = (type: string): ValidatorFn | undefined => {
  return entityValidators.get(type)?.validatorUpdate;
};
