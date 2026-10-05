import { ForbiddenAccess, ValidationError } from '../../config/errors';
import { isEmptyField, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../../database/utils';
import { getEntitiesMapFromCache } from '../../database/cache';
import { FROM_START_STR, UNTIL_END_STR } from '../../utils/format';
import { IDS_STIX, INPUT_CREATED_BY, INPUT_GRANTED_REFS, INPUT_MARKINGS } from '../../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import type { BasicStoreEntity, BasicStoreIdentifier } from '../../types/store';
import type { EditInput } from '../../generated/graphql';
import { internalFindByIds, internalLoadById } from '../../database/middleware-loader';
import { cleanMarkings } from '../../utils/markingDefinition-utils';
import { pairMarkings, pairOrganizations } from '../indicatorDeployment/indicatorDeployment-utils';
import {
  claimedGeneratedPairSighting,
  type GeneratedPairSighting,
  generatedPairSightingOf,
  generatedPairSightingStixId,
  isSightingReportContext,
  sightingPair,
  suppliedStixIds,
} from '../indicatorDeployment/indicatorDeployment-sightings';
import { registerEntityValidator, type ValidatorFn } from '../../schema/validator-register';
import type { AuthContext, AuthUser } from '../../types/user';
import { isBypassUser, SYSTEM_USER } from '../../utils/access';
import { findDeployedOn } from '../indicatorDeployment/indicatorDeployment-domain';
import {
  DEPLOYMENT_STATUS_EXPIRED,
  DEPLOYMENT_STATUS_PENDING,
  DEPLOYMENT_STATUSES,
  RELATION_DEPLOYED_ON,
  VALIDATION_STATUS_NOT_REQUESTED,
  VALIDATION_STATUSES,
} from '../indicatorDeployment/indicatorDeployment-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { findIocValidationConnectors } from './iocValidation-domain';
import { ENTITY_TYPE_IOC_VALIDATION_REQUEST } from './iocValidation-types';
import { isLifecycleWriter, isTrustedDeploymentReporter } from './iocValidation-utils';

const VALIDATION_FIELDS = ['validation_status', 'last_validation_at', 'validation_run_id'];
const LIFECYCLE_FIELDS = ['deployment_status', 'external_id', 'deployed_at', 'last_sync_at', 'removed_at', 'hit_count', 'first_hit_at', 'last_hit_at', 'last_hit_report_ids', 'error_message'];
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

// Whether the account is the one of the IOC validation connector a validation request was sent to.
const isConnectorUserOfRequest = async (context: AuthContext, user: AuthUser, requestId: string) => {
  const request = await internalLoadById<BasicStoreEntity & { connector_id?: string | null }>(
    context,
    SYSTEM_USER,
    requestId,
    { type: ENTITY_TYPE_IOC_VALIDATION_REQUEST },
  );
  if (!request?.connector_id) {
    return false;
  }
  const connectors = await findIocValidationConnectors(context, SYSTEM_USER);
  return connectors.some((connector: { internal_id?: string; connector_user_id?: string | null }) => connector.internal_id === request.connector_id
    && connector.connector_user_id === user.id);
};

// Validation fields of an existing deployment: the same accounts as iocValidationReportResults, i.e. the connector
// account that recorded the deployment, or an IOC validation connector: the one of the request the deployment is bound
// to, when it is bound to one.
const canChangeValidation = async (
  context: AuthContext,
  user: AuthUser,
  initial: { creator_id?: string | string[] | null; validation_run_id?: string | null } | undefined,
) => {
  if (!isLifecycleWriter(user)) {
    return false;
  }
  if (initial && isTrustedDeploymentReporter(initial, user)) {
    return true;
  }
  if (initial?.validation_run_id) {
    return isConnectorUserOfRequest(context, user, initial.validation_run_id);
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

// Marking operations of an upsert (upsertOperations), applied after its markings are added to the stored ones.
const upsertMarkingOperations = (instance: Record<string, unknown>) => ((instance.upsertOperations ?? []) as EditInput[])
  .filter((input) => input.key === INPUT_MARKINGS);

/**
 * Whether the upsert of an existing deployment leaves it with the markings of its indicator and of its security
 * platform: the markings it ends with are the stored ones, the markings of the input added, then its marking operations.
 */
export const coversUpsertPairMarkings = async (context: AuthContext, instance: Record<string, unknown>, existing: MarkedEnd) => {
  const from = instance.from as MarkedEnd | undefined;
  const to = instance.to as MarkedEnd | undefined;
  if (!from || !to) {
    return true;
  }
  const merged = [...markingIdsOf(existing[RELATION_OBJECT_MARKING] ?? []), ...markingIdsOf(instance[INPUT_MARKINGS] ?? [])];
  const operations = upsertMarkingOperations(instance);
  const effective = await markingsAfterEdits(context, merged, operations)
    ?? [...merged, ...operations.flatMap((input) => markingIdsOf(input.value))];
  return coversEndMarkings(context, effective, from, to);
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

/** Which generated sighting of its pair a stored sighting is, by the STIX ids it holds (see generatedPairSightingOf). */
export const generatedPairSighting = async (context: AuthContext, initial: Record<string, unknown> | undefined) => {
  const ids = [initial?.standard_id, ...((initial?.x_opencti_stix_ids as string[] | undefined) ?? [])].filter((id): id is string => typeof id === 'string');
  return generatedPairSightingOf(context, initial, ids);
};

export const isGeneratedPairSighting = async (context: AuthContext, initial: Record<string, unknown> | undefined) => {
  return (await generatedPairSighting(context, initial)) !== undefined;
};

/**
 * Whether an author value (an identity, its id, or a list of either) is an individual. When a platform organization is
 * set, the users of an individual read what it authored whatever the organizations it is shared with, so a pair
 * relationship authored by an individual would be read by users who cannot read its indicator or its security platform.
 */
export const isIndividualAuthor = async (context: AuthContext, value: unknown) => {
  const values = (Array.isArray(value) ? value : [value]).filter((author) => !isEmptyField(author));
  const types = await Promise.all(values.map(async (author) => {
    if (typeof author === 'string') {
      return (await internalLoadById<BasicStoreEntity>(context, SYSTEM_USER, author))?.entity_type;
    }
    return (author as { entity_type?: string }).entity_type;
  }));
  return types.includes(ENTITY_TYPE_IDENTITY_INDIVIDUAL);
};

// Whether edits give a pair relationship an individual as author (a field edit or a reference added).
const addsIndividualAuthor = async (context: AuthContext, editInputs: EditInput[]) => {
  const authorEdits = editInputs.filter((input) => input.key === INPUT_CREATED_BY && input.operation !== UPDATE_OPERATION_REMOVE);
  return authorEdits.length > 0 && isIndividualAuthor(context, authorEdits.flatMap((input) => input.value));
};

// Whether a creation or upsert input gives an individual as author, through its field or through an author operation.
const inputGivesIndividualAuthor = async (context: AuthContext, instance: Record<string, unknown>) => {
  if (await isIndividualAuthor(context, instance[INPUT_CREATED_BY])) {
    return true;
  }
  return addsIndividualAuthor(context, (instance.upsertOperations ?? []) as EditInput[]);
};

const refuseIndividualAuthor = (user: AuthUser) => {
  throw ForbiddenAccess('A deployment, like its hits and validation result sightings, is not authored by an individual: the users of an individual read what it authored, whatever its organizations', {
    user_id: user.id,
  });
};

/**
 * Whether a creation or upsert of a generated sighting leaves it with the markings of its indicator and of its security
 * platform, as the reporting mutations give it: a new sighting takes the markings of its input, an existing one keeps
 * the stored markings its upsert does not remove.
 */
const sightingInputCoversPairMarkings = async (context: AuthContext, instance: Record<string, unknown>) => {
  const inputCoversMarkings = await coversPairMarkings(context, instance);
  if (inputCoversMarkings && upsertMarkingOperations(instance).length === 0) {
    return true;
  }
  const stored = await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, suppliedStixIds(instance), { type: STIX_SIGHTING_RELATIONSHIP }) as BasicStoreEntity[];
  const existing = stored.find((sighting) => sighting) as MarkedEnd | undefined;
  return existing ? coversUpsertPairMarkings(context, instance, existing) : inputCoversMarkings;
};

/**
 * Whether the account writes the result sighting of a validation request for a pair: a lifecycle writer that is the
 * connector account of that request, or the trusted reporter of the deployment of the pair. The request is the one the
 * result belongs to, never the request the pair is bound to now: once a newer request takes the pair over, neither an
 * editor nor the connector of the newer request writes the result of an older one.
 */
const canWriteValidationResult = async (
  context: AuthContext,
  user: AuthUser,
  element: Record<string, unknown> | undefined,
  requestId: string,
) => {
  if (!isLifecycleWriter(user)) {
    return false;
  }
  const pair = sightingPair(element);
  const deployment = pair ? await findDeployedOn(context, SYSTEM_USER, pair.indicatorId, pair.platformId) : undefined;
  if (deployment && isTrustedDeploymentReporter(deployment, user)) {
    return true;
  }
  return isConnectorUserOfRequest(context, user, requestId);
};

// Generated sightings keep the markings of their pair and are never authored by an individual, for administrators too;
// the platform gives them the sharing of their pair (createRelation).
const validatorSightingCreation: ValidatorFn = async (context, user, instance) => {
  // Generic creation accepts a supplied STIX id: a claim of a generated sighting id is authorized as its report would be
  const claimed = await claimedGeneratedPairSighting(context, instance);
  if (claimed) {
    if (!await sightingInputCoversPairMarkings(context, instance)) {
      return refuseMarkings(user);
    }
    if (await inputGivesIndividualAuthor(context, instance)) {
      return refuseIndividualAuthor(user);
    }
  }
  if (!claimed || isBypassUser(user)) {
    return true;
  }
  return canWriteGeneratedSighting(context, user, instance, claimed);
};

const refuseGeneratedSightingWrite = (user: AuthUser) => {
  throw ForbiddenAccess('What a hits or validation result sighting records is written by indicatorReportHits or iocValidationReportResults only', {
    user_id: user.id,
  });
};

const refuseReservedIdRemoval = (user: AuthUser) => {
  throw ForbiddenAccess('A hits or validation result sighting keeps the identifier the platform gave it', { user_id: user.id });
};

// Apart from administrators, a generated sighting is written by its reporting mutation, and only by the accounts
// reporting it: the generic paths could otherwise take its identifier with a content the report would refuse.
const canWriteGeneratedSighting = async (
  context: AuthContext,
  user: AuthUser,
  element: Record<string, unknown> | undefined,
  generated: GeneratedPairSighting,
) => {
  if (generated.kind === 'hits' && !isLifecycleWriter(user)) {
    return refuseLifecycle(user);
  }
  if (generated.kind === 'validation_result' && !await canWriteValidationResult(context, user, element, generated.requestId)) {
    return refuseValidation(user);
  }
  return isSightingReportContext(context) ? true : refuseGeneratedSightingWrite(user);
};

// The STIX ids of a sighting once the edits of its x_opencti_stix_ids apply.
const stixIdsAfterEdits = (initial: Record<string, unknown> | undefined, editInputs: EditInput[]) => {
  let ids = ((initial?.x_opencti_stix_ids as string[] | undefined) ?? []).filter((id) => typeof id === 'string');
  editInputs.filter((input) => input.key === IDS_STIX).forEach((input) => {
    const values = (Array.isArray(input.value) ? input.value : [input.value]).filter((id): id is string => typeof id === 'string');
    if (input.operation === UPDATE_OPERATION_ADD) {
      ids = [...new Set([...ids, ...values])];
    } else if (input.operation === UPDATE_OPERATION_REMOVE) {
      ids = ids.filter((id) => !values.includes(id));
    } else {
      ids = values;
    }
  });
  return ids;
};

// What a generated sighting records: the hits of the pair (count and window), or the outcome of a validation.
const GENERATED_SIGHTING_CONTENT_FIELDS = ['attribute_count', 'x_opencti_negative', 'first_seen', 'last_seen', 'description'];

// Hits and validation result sightings keep the markings and the sharing of their pair, as deployments do, and the
// identifier the platform gave them, for administrators too; what they record is written by their report.
const validatorSightingUpdate: ValidatorFn = async (context, user, _instance, initial, editInputs = []) => {
  const touchesAccess = editInputs.some((input) => [INPUT_MARKINGS, INPUT_GRANTED_REFS, INPUT_CREATED_BY].includes(input.key));
  const touchesContent = editInputs.some((input) => GENERATED_SIGHTING_CONTENT_FIELDS.includes(input.key));
  const touchesIds = editInputs.some((input) => input.key === IDS_STIX);
  if (!touchesAccess && !touchesContent && !touchesIds) {
    return true;
  }
  const generated = await generatedPairSighting(context, initial);
  if (touchesIds) {
    const currentIds = [initial?.standard_id, ...((initial?.x_opencti_stix_ids as string[] | undefined) ?? [])].filter((id): id is string => typeof id === 'string');
    const editedIds = stixIdsAfterEdits(initial, editInputs);
    const reservedId = generated ? generatedPairSightingStixId(initial, generated) : undefined;
    if (reservedId && ![initial?.standard_id, ...editedIds].includes(reservedId)) {
      return refuseReservedIdRemoval(user);
    }
    // An edit giving a sighting the identifier of a generated sighting is a claim, authorized as on a creation
    const claimed = await generatedPairSightingOf(context, initial, editedIds.filter((id) => !currentIds.includes(id)));
    if (claimed && !isBypassUser(user)) {
      await canWriteGeneratedSighting(context, user, initial, claimed);
    }
  }
  if (!generated) {
    return true;
  }
  if (touchesAccess && !await keepsPairMarkings(context, initial, editInputs)) {
    return refuseMarkings(user);
  }
  if (touchesAccess && !await keepsPairSharing(context, initial, editInputs)) {
    return refuseSharing(user);
  }
  if (touchesAccess && await addsIndividualAuthor(context, editInputs)) {
    return refuseIndividualAuthor(user);
  }
  if (!touchesContent || isBypassUser(user)) {
    return true;
  }
  return canWriteGeneratedSighting(context, user, initial, generated);
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

// The generic paths store any string in an enum attribute; a status outside its list breaks every read of the field.
const STATUS_ALLOW_LISTS: Array<[string, readonly string[]]> = [['deployment_status', DEPLOYMENT_STATUSES], ['validation_status', VALIDATION_STATUSES]];

/** The status field of an input whose value is not one of the statuses of that field, if any. */
export const invalidStatusField = (instance: Record<string, unknown>) => STATUS_ALLOW_LISTS.find(([field, allowed]) => {
  const value = firstValue(instance[field]);
  return !isEmptyField(value) && !allowed.includes(value as string);
})?.[0];

const refuseInvalidStatus = (instance: Record<string, unknown>, field: string) => {
  throw ValidationError('Status is not one of the statuses of the field', field, { value: firstValue(instance[field]) });
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
  const invalidStatus = invalidStatusField(instance);
  if (invalidStatus) {
    return refuseInvalidStatus(instance, invalidStatus);
  }
  // A new deployment gets the markings of its input; an upsert keeps the stored ones it does not remove.
  const inputCoversMarkings = await coversPairMarkings(context, instance);
  if (!inputCoversMarkings || upsertMarkingOperations(instance).length > 0) {
    const stored = await findExistingDeployment(context, user, instance);
    if (!(stored ? await coversUpsertPairMarkings(context, instance, stored) : inputCoversMarkings)) {
      return refuseMarkings(user);
    }
  }
  // An upsert can fill an empty author or replace it through its operations, so both are checked as on a creation
  if (await inputGivesIndividualAuthor(context, instance)) {
    return refuseIndividualAuthor(user);
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
  const invalidStatus = invalidStatusField(instance);
  if (invalidStatus) {
    return refuseInvalidStatus(instance, invalidStatus);
  }
  // The pair access rules bind administrators too, as on creation; the bypass only lifts the lifecycle permissions.
  if (!await keepsPairMarkings(context, initial, editInputs)) {
    return refuseMarkings(user);
  }
  if (!await keepsPairSharing(context, initial, editInputs)) {
    return refuseSharing(user);
  }
  if (await addsIndividualAuthor(context, editInputs)) {
    return refuseIndividualAuthor(user);
  }
  if (isBypassUser(user)) {
    return true;
  }
  if (setsReservedStatus(instance)) {
    return refuseReservedStatus();
  }
  if (touchesLifecycleFields(instance) && !isLifecycleWriter(user)) {
    return refuseLifecycle(user);
  }
  const deployment = initial as { creator_id?: string | string[] | null; validation_run_id?: string | null } | undefined;
  if (touchesValidationFields(instance) && !await canChangeValidation(context, user, deployment)) {
    return refuseValidation(user);
  }
  return true;
};

registerEntityValidator(RELATION_DEPLOYED_ON, { validatorCreation, validatorUpdate });
registerEntityValidator(STIX_SIGHTING_RELATIONSHIP, { validatorCreation: validatorSightingCreation, validatorUpdate: validatorSightingUpdate });
