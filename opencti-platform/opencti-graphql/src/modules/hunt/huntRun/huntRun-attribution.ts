import { ForbiddenAccess } from '../../../config/errors';
import { isEmptyField } from '../../../database/utils';
import { registerEntityValidator, type ValidatorFn } from '../../../schema/validator-register';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../../schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../schema/stixSightingRelationship';
import type { AuthContext, AuthUser } from '../../../types/user';
import { HUNT_MANAGER_USER, isBypassUser } from '../../../utils/access';
import { findHuntRunById, isHuntRunConnectorCall } from './huntRun-domain';

// The observed data and the sightings a run found carry its id: the run and Source Intelligence count them as its evidence
export const ATTRIBUTE_HUNT_RUN_ID = 'x_opencti_hunt_run_id';

const attributedRunId = (value: unknown): string | null => {
  const [runId] = Array.isArray(value) ? value : [value];
  return isEmptyField(runId) ? null : String(runId);
};

/** Only the hunt connector a run was dispatched to, in the work of the dispatch, attributes an object to the run. */
const validateHuntRunAttribution = async (context: AuthContext, user: AuthUser, runId: string | null) => {
  if (!runId || isBypassUser(user)) {
    return true;
  }
  const run = await findHuntRunById(context, HUNT_MANAGER_USER, runId);
  if (!run || !await isHuntRunConnectorCall(context, user, run, context.workId)) {
    throw ForbiddenAccess('Only the hunt connector the run was dispatched to can attribute evidence to it', { runId });
  }
  return true;
};

const validatorCreation: ValidatorFn = async (context, user, instance) => {
  return validateHuntRunAttribution(context, user, attributedRunId(instance[ATTRIBUTE_HUNT_RUN_ID]));
};

// Clearing the attribution of an object takes the connector of the run it was attributed to
const validatorUpdate: ValidatorFn = async (context, user, instance, initial) => {
  if (!(ATTRIBUTE_HUNT_RUN_ID in instance)) {
    return true;
  }
  const runId = attributedRunId(instance[ATTRIBUTE_HUNT_RUN_ID]) ?? attributedRunId(initial?.[ATTRIBUTE_HUNT_RUN_ID]);
  return validateHuntRunAttribution(context, user, runId);
};

registerEntityValidator(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, { validatorCreation, validatorUpdate });
registerEntityValidator(STIX_SIGHTING_RELATIONSHIP, { validatorCreation, validatorUpdate });
