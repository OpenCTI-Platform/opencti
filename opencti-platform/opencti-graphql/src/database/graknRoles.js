import { invertObj } from 'ramda';
import { FunctionalError } from '../config/errors';
import {
  RELATION_ATTRIBUTED_TO,
  RELATION_AUTHORED_BY,
  RELATION_BELONGS,
  RELATION_CONTAINS,
  RELATION_CORRESPONDS,
  RELATION_CREATED_BY_REF,
  RELATION_DROPS,
  RELATION_EXTERNAL_REFERENCES,
  RELATION_GATHERING,
  RELATION_IMPERSONATES,
  RELATION_INDICATES,
  RELATION_KILL_CHAIN_PHASES,
  RELATION_LINKED,
  RELATION_MITIGATES,
  RELATION_OBJECT_MARKING_REFS,
  RELATION_OBJECT_REFS,
  RELATION_OBSERVABLE_REFS,
  RELATION_RELATED_TO,
  RELATION_RESOLVES,
  RELATION_SIGHTING,
  RELATION_OBJECT_LABEL,
  RELATION_TARGETS,
  RELATION_USES,
  RELATION_VARIANT_OF, RELATION_USER_ROLE, RELATION_ROLE_CAPABILITY,
} from '../utils/idGenerator';

export const ROLE_FROM = 'from';
export const ROLE_TO = 'to';

const rolesMap = {
  // region relation
  authorize: {
    client: ROLE_FROM,
    authorization: ROLE_TO,
  },
  migrate: {
    status: ROLE_FROM,
    state: ROLE_TO,
  },
  membership: {
    member: ROLE_FROM,
    grouping: ROLE_TO,
  },
  permission: {
    allowed: ROLE_FROM,
    allow: ROLE_TO,
  },
  [RELATION_USER_ROLE]: {
    client: ROLE_FROM,
    position: ROLE_TO,
  },
  [RELATION_ROLE_CAPABILITY]: {
    position: ROLE_FROM,
    capability: ROLE_TO,
  },
  // endregion
  // region relation_embedded
  [RELATION_AUTHORED_BY]: {
    so: ROLE_FROM,
    author: ROLE_TO,
  },
  [RELATION_OWNED_BY]: {
    so: ROLE_FROM,
    owner: ROLE_TO,
  },
  [RELATION_OBJECT_LABEL]: {
    so: ROLE_FROM,
    tagging: ROLE_TO,
  },
  // endregion
  // region stix_relation_embedded
  [RELATION_CREATED_BY_REF]: {
    so: ROLE_FROM,
    creator: ROLE_TO,
  },
  [RELATION_OBJECT_MARKING_REFS]: {
    so: ROLE_FROM,
    marking: ROLE_TO,
  },
  [RELATION_OBJECT_REFS]: {
    knowledge_aggregation: ROLE_FROM,
    so: ROLE_TO,
  },
  [RELATION_KILL_CHAIN_PHASES]: {
    phase_belonging: ROLE_FROM,
    kill_chain_phase: ROLE_TO,
  },
  [RELATION_EXTERNAL_REFERENCES]: {
    so: ROLE_FROM,
    external_reference: ROLE_TO,
  },
  [RELATION_OBSERVABLE_REFS]: {
    observables_aggregation: ROLE_FROM,
    soo: ROLE_TO,
  },
  // endregion
  // region stix_relation
  [RELATION_TARGETS]: {
    source: ROLE_FROM,
    target: ROLE_TO,
  },
  [RELATION_USES]: {
    user: ROLE_FROM,
    usage: ROLE_TO,
  },
  [RELATION_ATTRIBUTED_TO]: {
    attribution: ROLE_FROM,
    origin: ROLE_TO,
  },
  [RELATION_MITIGATES]: {
    mitigation: ROLE_FROM,
    problem: ROLE_TO,
  },
  [RELATION_INDICATES]: {
    indicator: ROLE_FROM,
    characterize: ROLE_TO,
  },
  [RELATION_COMES_AFTER]: {
    coming_from: ROLE_FROM,
    coming_after: ROLE_TO,
  },
  [RELATION_VARIANT_OF]: {
    variation: ROLE_FROM,
    original: ROLE_TO,
  },
  [RELATION_IMPERSONATES]: {
    dummy: ROLE_FROM,
    genuine: ROLE_TO,
  },
  [RELATION_RELATED_TO]: {
    relate_from: ROLE_FROM,
    relate_to: ROLE_TO,
  },
  [RELATION_LOCALIZATION]: {
    localized: ROLE_FROM,
    location: ROLE_TO,
  },
  [RELATION_DROPS]: {
    dropping: ROLE_FROM,
    dropped: ROLE_TO,
  },
  [RELATION_GATHERING]: {
    part_of: ROLE_FROM,
    gather: ROLE_TO,
  },
  [RELATION_SIGHTING]: {
    so: ROLE_FROM,
    sighted_in: ROLE_TO,
  },
  // endregion
  // region stix_observable_relation
  [RELATION_LINKED]: {
    link_from: ROLE_FROM,
    link_to: ROLE_TO,
  },
  [RELATION_RESOLVES]: {
    resolving: ROLE_FROM,
    resolved: ROLE_TO,
  },
  [RELATION_BELONGS]: {
    belonging_to: ROLE_FROM,
    belonged_to: ROLE_TO,
  },
  [RELATION_CORRESPONDS]: {
    correspond_from: ROLE_FROM,
    correspond_to: ROLE_TO,
  },
  [RELATION_CONTAINS]: {
    container: ROLE_FROM,
    contained: ROLE_TO,
  },
  // endregion
  // region testing
  role_test_missing: {
    source: ROLE_FROM,
  },
  // endregion
};

export const resolveNaturalRoles = (relationship) => {
  const definition = rolesMap[relationship];
  if (!definition) {
    throw FunctionalError(`Undefined directed roles for ${relationship}`);
  }
  const inverseDefinition = invertObj(definition);
  if (!inverseDefinition[ROLE_FROM] || !inverseDefinition[ROLE_TO]) {
    throw FunctionalError(`Cannot find from or to definition in ${relationship}`);
  }
  return definition;
};

export const isInversed = (relationType, fromRole) => {
  if (relationType && fromRole) {
    if (rolesMap[relationType]) {
      const resolvedFromRole = rolesMap[relationType][fromRole];
      return resolvedFromRole !== ROLE_FROM;
    }
  }
  return false;
};
