import { ForbiddenAccess, ValidationError } from '../../config/errors';
import { isEmptyField, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../../database/utils';
import { getEntitiesMapFromCache } from '../../database/cache';
import { FROM_START_STR, UNTIL_END_STR } from '../../utils/format';
import { INPUT_GRANTED_REFS, INPUT_MARKINGS } from '../../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import type { BasicStoreEntity, BasicStoreIdentifier } from '../../types/store';
import type { EditInput } from '../../generated/graphql';
import { fullEntitiesList, internalFindByIds } from '../../database/middleware-loader';
import { cleanMarkings } from '../../utils/markingDefinition-utils';
import { pairMarkings, pairOrganizations, validationResultSightingStixId } from '../indicatorDeployment/indicatorDeployment-utils';
import { registerEntityValidator, type ValidatorFn } from '../../schema/validator-register';
import type { AuthContext, AuthUser } from '../../types/user';
import { isBypassUser, SYSTEM_USER } from '../../utils/access';
import { findDeployedOn, hitsSightingStixId } from '../indicatorDeployment/indicatorDeployment-domain';
import { DEPLOYMENT_STATUS_EXPIRED, DEPLOYMENT_STATUS_PENDING, RELATION_DEPLOYED_ON, VALIDATION_STATUS_NOT_REQUESTED } from '../indicatorDeployment/indicatorDeployment-types';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { findIocValidationConnectors } from './iocValidation-domain';
import { ENTITY_TYPE_IOC_VALIDATION_REQUEST } from './iocValidation-types';
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
type SharedEnd = { [RELATION_GRANTED_TO]?: string[] | null };

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

// Organization ids given in any form as internal ids (a standard or STIX id is resolved, an internal id kept).
const toOrganizationInternalIds = async (context: AuthContext, ids: string[]) => {
  const external = ids.filter((id) => id.includes('--'));
  if (external.length === 0) {
    return ids;
  }
  const organizations = await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, external, { type: ENTITY_TYPE_IDENTITY_ORGANIZATION }) as BasicStoreEntity[];
  const byId = new Map<string, string>();
  organizations.filter((organization) => organization).forEach((organization) => {
    [organization.internal_id, organization.standard_id, ...(organization.x_opencti_stix_ids ?? [])].forEach((id) => byId.set(id, organization.internal_id));
  });
  return ids.map((id) => byId.get(id) ?? id);
};

/**
 * Whether edits keep a pair relationship shared with the organizations of both its ends only: its sharing can be
 * narrowed, never widened to an organization one of its ends is not shared with.
 */
export const keepsPairSharing = async (context: AuthContext, initial: Record<string, unknown> | undefined, editInputs: EditInput[]) => {
  const from = initial?.from as SharedEnd | undefined;
  const to = initial?.to as SharedEnd | undefined;
  const sharingEdits = editInputs.filter((input) => input.key === INPUT_GRANTED_REFS && input.operation !== UPDATE_OPERATION_REMOVE);
  if (!from || !to || sharingEdits.length === 0) {
    return true;
  }
  const allowed = new Set(pairOrganizations(from, to));
  const added = await toOrganizationInternalIds(context, sharingEdits.flatMap((input) => markingIdsOf(input.value)));
  return added.every((id) => allowed.has(id));
};

const refuseSharing = (user: AuthUser) => {
  throw ForbiddenAccess('A deployment and its sightings are shared with the organizations of both its indicator and its security platform only', { user_id: user.id });
};

/**
 * Whether a sighting is one the platform generates for an (indicator, security platform) pair: the hits sighting of the
 * pair, or the result sighting of a validation request that included it (both identified by their deterministic id).
 */
export const isGeneratedPairSighting = async (context: AuthContext, initial: Record<string, unknown> | undefined) => {
  const from = initial?.from as { entity_type?: string; internal_id?: string } | undefined;
  const to = initial?.to as { entity_type?: string; internal_id?: string } | undefined;
  if (from?.entity_type !== ENTITY_TYPE_INDICATOR || to?.entity_type !== ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM || !from.internal_id || !to.internal_id) {
    return false;
  }
  const indicatorId = from.internal_id;
  const platformId = to.internal_id;
  const ids = new Set([initial?.standard_id, ...((initial?.x_opencti_stix_ids as string[] | undefined) ?? [])].filter((id): id is string => typeof id === 'string'));
  if (ids.has(hitsSightingStixId(indicatorId, platformId))) {
    return true;
  }
  let generated = false;
  await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_IOC_VALIDATION_REQUEST], {
    filters: { mode: 'and', filters: [{ key: ['indicator_ids'], values: [indicatorId] }, { key: ['platform_ids'], values: [platformId] }], filterGroups: [] },
    noFiltersChecking: true,
    baseData: true,
    first: 500,
    callback: async (requests: BasicStoreEntity[]) => {
      generated = requests.some((request) => ids.has(validationResultSightingStixId(request.internal_id, indicatorId, platformId)));
      return !generated;
    },
  } as never);
  return generated;
};

// Hits and validation result sightings keep the markings and the sharing of their pair, as deployments do.
const validatorSightingUpdate: ValidatorFn = async (context, user, _instance, initial, editInputs = []) => {
  const touchesAccess = editInputs.some((input) => input.key === INPUT_MARKINGS || input.key === INPUT_GRANTED_REFS);
  if (!touchesAccess || isBypassUser(user) || !await isGeneratedPairSighting(context, initial)) {
    return true;
  }
  if (!await keepsPairMarkings(context, initial, editInputs)) {
    return refuseMarkings(user);
  }
  if (!await keepsPairSharing(context, initial, editInputs)) {
    return refuseSharing(user);
  }
  return true;
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
  throw ForbiddenAccess('A deployment, like its hits and validation result sightings, carries the markings of its indicator and of its security platform', {
    user_id: user.id,
  });
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
  if (!await keepsPairSharing(context, initial, editInputs)) {
    return refuseSharing(user);
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
registerEntityValidator(STIX_SIGHTING_RELATIONSHIP, { validatorUpdate: validatorSightingUpdate });
