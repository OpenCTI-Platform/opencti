import { ForbiddenAccess } from '../../../config/errors';
import { getExistingRelations } from '../../../database/middleware';
import { internalFindByIds } from '../../../database/middleware-loader';
import { isEmptyField, isNotEmptyField } from '../../../database/utils';
import { getInputIds } from '../../../schema/identifier';
import { registerEntityValidator, type ValidatorFn } from '../../../schema/validator-register';
import { INPUT_GRANTED_REFS, INPUT_MARKINGS } from '../../../schema/general';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../../schema/stixDomainObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../schema/stixRefRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../schema/stixSightingRelationship';
import type { BasicStoreObject } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import { HUNT_MANAGER_USER, isBypassUser, isServiceAccountUser, isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT, SYSTEM_USER } from '../../../utils/access';
import { isReadableByReadersOf } from '../hunt-iocs';
import { findByIds } from '../hunt-loaders';
import { type BasicStoreEntityHuntRun } from './huntRun-types';
import { findHuntRunById, isHuntRunConnectorCall } from './huntRun-domain';

// The observed data and the sightings a run found carry its id: the run and Source Intelligence count them as its evidence
export const ATTRIBUTE_HUNT_RUN_ID = 'x_opencti_hunt_run_id';
// The sighting a hunt keeps up to date names the hunt: only the platform sets it (hunt-sightings)
const ATTRIBUTE_SIGHTING_HUNT_ID = 'x_opencti_hunt_id';

type EvidenceAccess = { [RELATION_OBJECT_MARKING]: string[]; [RELATION_GRANTED_TO]: string[] };

const attributedRunId = (value: unknown): string | null => {
  const [runId] = Array.isArray(value) ? value : [value];
  return isEmptyField(runId) ? null : String(runId);
};

// A reference of an input is an id before the references are resolved (an upsert) and the element after
const referenceIds = (references: unknown) => (Array.isArray(references) ? references : [references])
  .filter((reference) => isNotEmptyField(reference))
  .map((reference) => (typeof reference === 'string' ? reference : String((reference as BasicStoreObject).internal_id)));

/** The organizations the platform shares a new object with, as the creation stores them. */
const createdOrganizations = async (context: AuthContext, user: AuthUser, requested: unknown) => {
  const ids = referenceIds(requested);
  if (isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && ids.length > 0) {
    const organizations = await findByIds<BasicStoreObject>(context, SYSTEM_USER, ids);
    return organizations.map((organization) => organization.internal_id);
  }
  if (!context.user_inside_platform_organization || (isServiceAccountUser(user) && isNotEmptyField(user.organizations))) {
    return (user.organizations ?? []).map((organization) => organization.internal_id);
  }
  return [];
};

/**
 * The stored objects a creation upserts into, found as the creation finds them. An ordinary sighting never merges into
 * the sighting a hunt keeps, unless it names its id.
 */
const upsertedObjects = async (context: AuthContext, user: AuthUser, type: string, instance: Record<string, unknown>): Promise<BasicStoreObject[]> => {
  if (type === STIX_SIGHTING_RELATIONSHIP) {
    const requestedIds = new Set<string>(getInputIds(type, instance, false));
    const matched = await getExistingRelations(context, user, instance) as (BasicStoreObject & { x_opencti_hunt_id?: string })[];
    return matched.filter((relation) => isEmptyField(relation.x_opencti_hunt_id)
      || [relation.internal_id, relation.standard_id, ...(relation.x_opencti_stix_ids ?? [])].some((id) => requestedIds.has(id)));
  }
  const ids = [...getInputIds(type, instance, undefined), ...(context.previousStandard ? [context.previousStandard] : [])];
  return await internalFindByIds(context, SYSTEM_USER, ids, { type }) as BasicStoreObject[];
};

/**
 * The evidence of a run is at least as restricted as the run: every marking of the run is covered by a marking of the
 * evidence of the same type and at least the same level and, with a platform organization, the evidence is shared with
 * no organization the run is not shared with. Otherwise a user who cannot read the run could read what it found.
 */
const validateEvidenceAccess = async (context: AuthContext, run: BasicStoreEntityHuntRun, evidence: () => Promise<EvidenceAccess[]>) => {
  const readable = await Promise.all((await evidence()).map((access) => isReadableByReadersOf(context, access, run)));
  if (readable.some((isReadable) => !isReadable)) {
    throw ForbiddenAccess('The evidence of a run carries at least the markings of the run and no organization the run is not shared with', { runId: run.internal_id });
  }
};

/** Only the hunt connector a run was dispatched to, in the work of the dispatch, attributes an object to the run. */
const validateHuntRunAttribution = async (context: AuthContext, user: AuthUser, runId: string | null, evidence: (() => Promise<EvidenceAccess[]>) | null) => {
  if (!runId || isBypassUser(user)) {
    return true;
  }
  const run = await findHuntRunById(context, HUNT_MANAGER_USER, runId);
  if (!run || !await isHuntRunConnectorCall(context, user, run, context.workId)) {
    throw ForbiddenAccess('Only the hunt connector the run was dispatched to can attribute evidence to it', { runId });
  }
  if (evidence) {
    await validateEvidenceAccess(context, run, evidence);
  }
  return true;
};

// A creation that upserts into stored objects keeps their markings and organizations, the incoming ones being added
// only when the confidence allows it or to fill an empty field: as for an update, each stored object attributed to a
// run has to be as restricted as the run, its empty markings filled by the incoming ones
const validatorCreationOf = (type: string): ValidatorFn => async (context, user, instance) => {
  return validateHuntRunAttribution(context, user, attributedRunId(instance[ATTRIBUTE_HUNT_RUN_ID]), async () => {
    const incoming: EvidenceAccess = {
      [RELATION_OBJECT_MARKING]: referenceIds(instance[INPUT_MARKINGS]),
      [RELATION_GRANTED_TO]: await createdOrganizations(context, user, instance[INPUT_GRANTED_REFS]),
    };
    const stored = (await upsertedObjects(context, user, type, instance)).map((element): EvidenceAccess => {
      const markings = referenceIds(element[RELATION_OBJECT_MARKING]);
      return {
        [RELATION_OBJECT_MARKING]: markings.length > 0 ? markings : incoming[RELATION_OBJECT_MARKING],
        [RELATION_GRANTED_TO]: referenceIds(element[RELATION_GRANTED_TO]),
      };
    });
    return [incoming, ...stored];
  });
};

// Clearing the attribution of an object takes the connector of the run it was attributed to; attributing an object
// already stored to a run takes it to be as restricted as the run. A later change of the markings or organizations of
// attributed evidence is the decision of a user allowed to make it, as for any object: it is not checked against the run
const validatorUpdate: ValidatorFn = async (context, user, instance, initial) => {
  if (!(ATTRIBUTE_HUNT_RUN_ID in instance)) {
    return true;
  }
  const attributed = attributedRunId(instance[ATTRIBUTE_HUNT_RUN_ID]);
  if (!attributed) {
    return validateHuntRunAttribution(context, user, attributedRunId(initial?.[ATTRIBUTE_HUNT_RUN_ID]), null);
  }
  // The stored access is what the attribution is checked against: a patch changing it as well would escape the check
  if (!isBypassUser(user) && (INPUT_MARKINGS in instance || INPUT_GRANTED_REFS in instance)) {
    throw ForbiddenAccess('An object is attributed to a run in a change of its own: set its markings and organizations first', { runId: attributed });
  }
  return validateHuntRunAttribution(context, user, attributed, async () => [{
    [RELATION_OBJECT_MARKING]: referenceIds(initial?.[RELATION_OBJECT_MARKING]),
    [RELATION_GRANTED_TO]: referenceIds(initial?.[RELATION_GRANTED_TO]),
  }]);
};

// A sighting names the hunt that keeps it only when the platform writes it: a connector or a user never sets, changes
// or clears it (an update carries the edited keys only)
const validateSightingHunt = (user: AuthUser, touched: boolean) => {
  if (touched && !isBypassUser(user)) {
    throw ForbiddenAccess('Only the platform keeps the sighting of a hunt up to date');
  }
};

const validatorCreation = validatorCreationOf(ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
const sightingEvidenceValidatorCreation = validatorCreationOf(STIX_SIGHTING_RELATIONSHIP);

const sightingValidatorCreation: ValidatorFn = async (context, user, instance) => {
  validateSightingHunt(user, !isEmptyField(instance[ATTRIBUTE_SIGHTING_HUNT_ID]));
  return sightingEvidenceValidatorCreation(context, user, instance);
};

const sightingValidatorUpdate: ValidatorFn = async (context, user, instance, initial) => {
  validateSightingHunt(user, ATTRIBUTE_SIGHTING_HUNT_ID in instance);
  return validatorUpdate(context, user, instance, initial);
};

registerEntityValidator(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, { validatorCreation, validatorUpdate });
registerEntityValidator(STIX_SIGHTING_RELATIONSHIP, { validatorCreation: sightingValidatorCreation, validatorUpdate: sightingValidatorUpdate });
