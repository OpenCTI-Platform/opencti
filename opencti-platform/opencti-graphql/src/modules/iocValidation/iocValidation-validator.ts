import { ForbiddenAccess, ValidationError } from '../../config/errors';
import { isEmptyField, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../../database/utils';
import { getEntitiesMapFromCache } from '../../database/cache';
import { FROM_START_STR, UNTIL_END_STR } from '../../utils/format';
import { INPUT_MARKINGS } from '../../schema/general';
import { RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import type { BasicStoreIdentifier } from '../../types/store';
import type { EditInput } from '../../generated/graphql';
import { cleanMarkings } from '../../utils/markingDefinition-utils';
import { pairMarkings } from '../indicatorDeployment/indicatorDeployment-utils';
import { registerEntityValidator, type ValidatorFn } from '../../schema/validator-register';
import type { AuthContext, AuthUser } from '../../types/user';
import { isBypassUser, SYSTEM_USER } from '../../utils/access';
import { findDeployedOn } from '../indicatorDeployment/indicatorDeployment-domain';
import { DEPLOYMENT_STATUS_EXPIRED, DEPLOYMENT_STATUS_PENDING, RELATION_DEPLOYED_ON, VALIDATION_STATUS_NOT_REQUESTED } from '../indicatorDeployment/indicatorDeployment-types';
import { findIocValidationConnectors } from './iocValidation-domain';
import { isLifecycleWriter, isTrustedDeploymentReporter } from './iocValidation-utils';

const VALIDATION_FIELDS = ['validation_status', 'last_validation_at', 'validation_run_id'];
const LIFECYCLE_FIELDS = ['deployment_status', 'external_id', 'deployed_at', 'last_sync_at', 'removed_at', 'hit_count', 'first_hit_at', 'last_hit_at', 'error_message'];
// Values of a deployment that records nothing yet, which any editor may give a new relationship.
const LIFECYCLE_DEFAULTS: Record<string, unknown> = { deployment_status: DEPLOYMENT_STATUS_PENDING, hit_count: 0 };

const firstValue = (raw: unknown) => (Array.isArray(raw) ? raw[0] : raw);
const isProvided = (instance: Record<string, unknown>, field: string) => field in instance && instance[field] !== undefined;

/** Whether a creation input records validation proof: anything but "not requested" without run reference. */
export const carriesValidationProof = (instance: Record<string, unknown>) => VALIDATION_FIELDS.some((field) => {
  const value = firstValue(instance[field]);
  if (isEmptyField(value)) {
    return false;
  }
  return field !== 'validation_status' || value !== VALIDATION_STATUS_NOT_REQUESTED;
});

/** Whether an input changes a validation field, whatever the value (erasing proof is as sensitive as writing it). */
export const touchesValidationFields = (instance: Record<string, unknown>) => VALIDATION_FIELDS.some((field) => isProvided(instance, field));

/** Whether a creation input records deployment state: any lifecycle value but the defaults of a new deployment. */
export const carriesLifecycleState = (instance: Record<string, unknown>) => LIFECYCLE_FIELDS.some((field) => {
  const value = firstValue(instance[field]);
  return !isEmptyField(value) && LIFECYCLE_DEFAULTS[field] !== value;
});

/** Whether an input changes a lifecycle field, whatever the value (a reset erases the recorded state). */
export const touchesLifecycleFields = (instance: Record<string, unknown>) => LIFECYCLE_FIELDS.some((field) => isProvided(instance, field));

export { isLifecycleWriter };

const isIocValidationConnectorUser = async (context: AuthContext, user: AuthUser) => {
  const connectors = await findIocValidationConnectors(context, SYSTEM_USER);
  return connectors.some((connector: { connector_user_id?: string | null }) => connector.connector_user_id === user.id);
};

const refuseValidation = (user: AuthUser) => {
  throw ForbiddenAccess('Validation results of a deployment are recorded by an OpenAEV IOC validation connector or reported with iocValidationReportResults', {
    user_id: user.id,
  });
};

const refuseLifecycle = (user: AuthUser) => {
  throw ForbiddenAccess('The deployment state is written by the security platform integrations (indicatorReportDeployment, indicatorReportHits) or imported by a connector', {
    user_id: user.id,
  });
};

// Validation fields of an existing deployment: the same accounts as iocValidationReportResults,
// i.e. an IOC validation connector or the connector account that recorded the deployment.
const canChangeValidation = async (context: AuthContext, user: AuthUser, initial: { creator_id?: string | string[] | null } | undefined) => {
  if (!isLifecycleWriter(user)) {
    return false;
  }
  if (initial && isTrustedDeploymentReporter(initial, user)) {
    return true;
  }
  return isIocValidationConnectorUser(context, user);
};

const findExistingDeployment = async (context: AuthContext, user: AuthUser, instance: Record<string, unknown>) => {
  const from = instance.from as { internal_id?: string } | undefined;
  const to = instance.to as { internal_id?: string } | undefined;
  if (!from?.internal_id || !to?.internal_id) {
    return undefined;
  }
  return findDeployedOn(context, user, from.internal_id, to.internal_id);
};

const markingIdsOf = (values: unknown): string[] => (Array.isArray(values) ? values : [values])
  .map((value) => (typeof value === 'string' ? value : (value as { internal_id?: string } | null)?.internal_id))
  .filter((id): id is string => typeof id === 'string' && id.length > 0);

type MarkedEnd = { [RELATION_OBJECT_MARKING]?: string[] | null };

// Marking ids given in any form (internal, standard or STIX id) as internal ids.
const toMarkingInternalIds = async (context: AuthContext, ids: string[]) => {
  const markingsMap = await getEntitiesMapFromCache<BasicStoreIdentifier>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  return ids.map((id) => markingsMap.get(id)?.internal_id ?? id);
};

// Whether markings are at least as strict as those of both ends: adding the markings of the ends would not make the
// cleaned markings (highest of each type) any stricter.
const coversEndMarkings = async (context: AuthContext, markingIds: string[], from: MarkedEnd, to: MarkedEnd) => {
  const provided = await toMarkingInternalIds(context, markingIds);
  const cleaned = await cleanMarkings(context, [...provided, ...pairMarkings(from, to)]);
  return cleaned.every((marking: { internal_id?: string } | string) => provided.includes(typeof marking === 'string' ? marking : marking.internal_id ?? ''));
};

/**
 * Whether a created or upserted deployment carries the markings of its indicator and of its security platform, as the
 * write-back mutations give it.
 */
export const coversPairMarkings = async (context: AuthContext, instance: Record<string, unknown>) => {
  const from = instance.from as MarkedEnd | undefined;
  const to = instance.to as MarkedEnd | undefined;
  if (!from || !to) {
    return true;
  }
  return coversEndMarkings(context, markingIdsOf(instance[INPUT_MARKINGS]), from, to);
};

/**
 * Markings of a deployment after edits of its markings, applied in order, or undefined when no edit can relax them
 * (additions only: an addition of a lower marking of a type already present never replaces the higher one).
 */
export const markingsAfterEdits = async (context: AuthContext, current: string[], editInputs: EditInput[]) => {
  const markingEdits = editInputs.filter((input) => input.key === INPUT_MARKINGS);
  if (markingEdits.every((input) => input.operation === UPDATE_OPERATION_ADD)) {
    return undefined;
  }
  let result = await toMarkingInternalIds(context, current);
  for (let index = 0; index < markingEdits.length; index += 1) {
    const { operation, value } = markingEdits[index];
    const values = await toMarkingInternalIds(context, markingIdsOf(value));
    if (operation === UPDATE_OPERATION_ADD) {
      result = [...new Set([...result, ...values])];
    } else if (operation === UPDATE_OPERATION_REMOVE) {
      result = result.filter((id) => !values.includes(id));
    } else {
      result = values;
    }
  }
  return result;
};

/**
 * Whether edits leave a deployment at least as restricted as its indicator and its security platform: a marking of an
 * end can be raised on the deployment, never removed nor replaced by a lower one.
 */
export const keepsPairMarkings = async (context: AuthContext, initial: Record<string, unknown> | undefined, editInputs: EditInput[]) => {
  const from = initial?.from as MarkedEnd | undefined;
  const to = initial?.to as MarkedEnd | undefined;
  if (!from || !to) {
    return true;
  }
  const result = await markingsAfterEdits(context, markingIdsOf(initial?.[RELATION_OBJECT_MARKING] ?? []), editInputs);
  return result === undefined || coversEndMarkings(context, result, from, to);
};

/**
 * Whether an input gives a deployment a validity window. A deployment has none (its dates are deployed_at,
 * last_sync_at and removed_at): without start and stop times its identity is the pair alone, so every creation or
 * import of the same pair upserts the one deployment of the pair instead of adding a second one.
 */
export const setsValidityWindow = (instance: Record<string, unknown>) => [['start_time', FROM_START_STR], ['stop_time', UNTIL_END_STR]]
  .some(([field, defaultValue]) => {
    const value = firstValue(instance[field]);
    if (isEmptyField(value)) {
      return false;
    }
    const time = new Date(value as string).getTime();
    return Number.isNaN(time) || time !== new Date(defaultValue).getTime();
  });

const refuseValidityWindow = () => {
  throw ValidationError('A deployment has no start or stop time: one deployment exists per indicator and security platform', 'start_time');
};

// `expired` is the deployment manager's decision when no removal confirmation arrives in time, never a report.
const setsReservedStatus = (instance: Record<string, unknown>) => firstValue(instance.deployment_status) === DEPLOYMENT_STATUS_EXPIRED;

const refuseReservedStatus = () => {
  throw ValidationError('Deployment status is invalid or reserved to the platform', 'status', { status: DEPLOYMENT_STATUS_EXPIRED });
};

const refuseMarkings = (user: AuthUser) => {
  throw ForbiddenAccess('A deployment carries the markings of its indicator and of its security platform', { user_id: user.id });
};

// Creation, including the upsert of an existing deployment (stixCoreRelationshipAdd with update, bundle ingestion),
// whose writes never reach the edition validator: a new deployment only takes the defaults from a regular editor,
// and an existing one is changed under the edition rules, resets included.
const validatorCreation: ValidatorFn = async (context, user, instance) => {
  if (setsValidityWindow(instance)) {
    return refuseValidityWindow();
  }
  if (!await coversPairMarkings(context, instance)) {
    return refuseMarkings(user);
  }
  if (isBypassUser(user)) {
    return true;
  }
  if (setsReservedStatus(instance)) {
    return refuseReservedStatus();
  }
  const lifecycleWriter = isLifecycleWriter(user);
  if (carriesLifecycleState(instance) && !lifecycleWriter) {
    return refuseLifecycle(user);
  }
  const recordsProof = carriesValidationProof(instance);
  const resetsLifecycle = touchesLifecycleFields(instance) && !lifecycleWriter;
  const changesValidation = touchesValidationFields(instance);
  if (!resetsLifecycle && !changesValidation) {
    return true;
  }
  const existing = await findExistingDeployment(context, user, instance);
  if (!existing) {
    // A new deployment that already records an outcome comes from an IOC validation connector only.
    if (recordsProof && !await isIocValidationConnectorUser(context, user)) {
      return refuseValidation(user);
    }
    return true;
  }
  if (resetsLifecycle) {
    return refuseLifecycle(user);
  }
  // An existing deployment is changed under the edition rules: its reporting connector included, resets included.
  if (!await canChangeValidation(context, user, existing)) {
    return refuseValidation(user);
  }
  return true;
};

const validatorUpdate: ValidatorFn = async (context, user, instance, initial, editInputs = []) => {
  if (setsValidityWindow(instance)) {
    return refuseValidityWindow();
  }
  if (isBypassUser(user)) {
    return true;
  }
  if (!await keepsPairMarkings(context, initial, editInputs)) {
    return refuseMarkings(user);
  }
  if (setsReservedStatus(instance)) {
    return refuseReservedStatus();
  }
  if (touchesLifecycleFields(instance) && !isLifecycleWriter(user)) {
    return refuseLifecycle(user);
  }
  if (touchesValidationFields(instance) && !await canChangeValidation(context, user, initial as { creator_id?: string | string[] | null } | undefined)) {
    return refuseValidation(user);
  }
  return true;
};

registerEntityValidator(RELATION_DEPLOYED_ON, { validatorCreation, validatorUpdate });
