import { invertObj } from 'ramda';

export const ROLE_FROM = 'from';
const ROLE_TO = 'to';

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
  user_role: {
    client: ROLE_FROM,
    position: ROLE_TO,
  },
  role_capability: {
    position: ROLE_FROM,
    capability: ROLE_TO,
  },
  // endregion
  // region relation_embedded
  authored_by: {
    so: ROLE_FROM,
    author: ROLE_TO,
  },
  owned_by: {
    so: ROLE_FROM,
    owner: ROLE_TO,
  },
  tagged: {
    so: ROLE_FROM,
    tagging: ROLE_TO,
  },
  // endregion
  // region stix_relation_embedded
  created_by_ref: {
    so: ROLE_FROM,
    creator: ROLE_TO,
  },
  object_marking_refs: {
    so: ROLE_FROM,
    marking: ROLE_TO,
  },
  object_refs: {
    knowledge_aggregation: ROLE_FROM,
    so: ROLE_TO,
  },
  kill_chain_phases: {
    phase_belonging: ROLE_FROM,
    kill_chain_phase: ROLE_TO,
  },
  external_references: {
    so: ROLE_FROM,
    external_reference: ROLE_TO,
  },
  observable_refs: {
    observables_aggregation: ROLE_FROM,
    soo: ROLE_TO,
  },
  // endregion
  // region stix_relation
  targets: {
    source: ROLE_FROM,
    target: ROLE_TO,
  },
  uses: {
    user: ROLE_FROM,
    usage: ROLE_TO,
  },
  'attributed-to': {
    attribution: ROLE_FROM,
    origin: ROLE_TO,
  },
  mitigates: {
    mitigation: ROLE_FROM,
    problem: ROLE_TO,
  },
  indicates: {
    indicator: ROLE_FROM,
    characterize: ROLE_TO,
  },
  'comes-after': {
    coming_from: ROLE_FROM,
    coming_after: ROLE_TO,
  },
  'variant-of': {
    variation: ROLE_FROM,
    original: ROLE_TO,
  },
  impersonates: {
    dummy: ROLE_FROM,
    genuine: ROLE_TO,
  },
  'related-to': {
    relate_from: ROLE_FROM,
    relate_to: ROLE_TO,
  },
  localization: {
    localized: ROLE_FROM,
    location: ROLE_TO,
  },
  drops: {
    dropping: ROLE_FROM,
    dropped: ROLE_TO,
  },
  gathering: {
    part_of: ROLE_FROM,
    gather: ROLE_TO,
  },
  // endregion
  // region stix_observable_relation
  linked: {
    link_from: ROLE_FROM,
    link_to: ROLE_TO,
  },
  resolves: {
    resolving: ROLE_FROM,
    resolved: ROLE_TO,
  },
  belongs: {
    belonging_to: ROLE_FROM,
    belonged_to: ROLE_TO,
  },
  corresponds: {
    correspond_from: ROLE_FROM,
    correspond_to: ROLE_TO,
  },
  contains: {
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
    throw new Error(`Undefined directed roles for ${relationship}`);
  }
  const inverseDefinition = invertObj(definition);
  if (!inverseDefinition[ROLE_FROM] || !inverseDefinition[ROLE_TO]) {
    throw new Error(`Cannot find from or to definition in ${relationship}`);
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
