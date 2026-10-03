import { ForbiddenAccess } from '../../config/errors';
import { isEmptyField } from '../../database/utils';
import { registerEntityValidator, type ValidatorFn } from '../../schema/validator-register';
import type { AuthContext, AuthUser } from '../../types/user';
import { isBypassUser, SYSTEM_USER } from '../../utils/access';
import { RELATION_DEPLOYED_ON, VALIDATION_STATUS_NOT_REQUESTED } from '../indicatorDeployment/indicatorDeployment-types';
import { findIocValidationConnectors } from './iocValidation-domain';
import { isDeploymentReporter } from './iocValidation-utils';

const VALIDATION_FIELDS = ['validation_status', 'last_validation_at', 'validation_run_id'];

const firstValue = (raw: unknown) => (Array.isArray(raw) ? raw[0] : raw);

/** Whether a creation input records validation proof: anything but "not requested" without run reference. */
export const carriesValidationProof = (instance: Record<string, unknown>) => VALIDATION_FIELDS.some((field) => {
  const value = firstValue(instance[field]);
  if (isEmptyField(value)) {
    return false;
  }
  return field !== 'validation_status' || value !== VALIDATION_STATUS_NOT_REQUESTED;
});

/** Whether an update changes a validation field, whatever the value (erasing proof is as sensitive as writing it). */
export const touchesValidationFields = (instance: Record<string, unknown>) => VALIDATION_FIELDS.some((field) => field in instance);

const isIocValidationConnectorUser = async (context: AuthContext, user: AuthUser) => {
  const connectors = await findIocValidationConnectors(context, SYSTEM_USER);
  return connectors.some((connector: { connector_user_id?: string | null }) => connector.connector_user_id === user.id);
};

const refuse = (user: AuthUser) => {
  throw ForbiddenAccess('Validation results of a deployment are recorded by an OpenAEV IOC validation connector or reported with iocValidationReportResults', {
    user_id: user.id,
  });
};

// Creation and upsert (bundle ingestion included): only an IOC validation connector or an administrator records proof.
const validatorCreation: ValidatorFn = async (context, user, instance) => {
  if (!carriesValidationProof(instance) || isBypassUser(user) || await isIocValidationConnectorUser(context, user)) {
    return true;
  }
  return refuse(user);
};

// Edition: the same accounts as iocValidationReportResults, i.e. also the account that recorded the deployment.
const validatorUpdate: ValidatorFn = async (context, user, instance, initial) => {
  if (!touchesValidationFields(instance) || isBypassUser(user)) {
    return true;
  }
  if (initial && isDeploymentReporter(initial as { creator_id?: string | string[] | null }, user.id)) {
    return true;
  }
  if (await isIocValidationConnectorUser(context, user)) {
    return true;
  }
  return refuse(user);
};

registerEntityValidator(RELATION_DEPLOYED_ON, { validatorCreation, validatorUpdate });
