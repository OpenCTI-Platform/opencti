export const rolesMap = {
  // region relation
  authorize: {
    client: 'from',
    authorization: 'to'
  },
  migrate: {
    status: 'from',
    state: 'to'
  },
  membership: {
    member: 'from',
    grouping: 'to'
  },
  permission: {
    allowed: 'from',
    allow: 'to'
  },
  // endregion
  // region relation_embedded
  authored_by: {
    so: 'from',
    author: 'to'
  },
  owned_by: {
    so: 'from',
    owner: 'to'
  },
  tagged: {
    so: 'from',
    tagging: 'to'
  },
  // endregion
  // region stix_relation_embedded
  created_by_ref: {
    so: 'from',
    creator: 'to'
  },
  object_marking_refs: {
    so: 'from',
    marking: 'to'
  },
  object_refs: {
    knowledge_aggregation: 'from',
    so: 'to'
  },
  kill_chain_phases: {
    phase_belonging: 'from',
    kill_chain_phase: 'to'
  },
  external_references: {
    so: 'from',
    external_reference: 'to'
  },
  // endregion
  // region stix_relation
  targets: {
    source: 'from',
    target: 'to'
  },
  uses: {
    user: 'from',
    usage: 'to'
  },
  'attributed-to': {
    origin: 'from',
    attribution: 'to'
  },
  mitigates: {
    mitigation: 'from',
    problem: 'to'
  },
  indicates: {
    indicator: 'from',
    characterize: 'to'
  },
  'variant-of': {
    variation: 'from',
    original: 'to'
  },
  impersonates: {
    dummy: 'from',
    genuine: 'to'
  },
  'related-to': {
    relate_from: 'from',
    relate_to: 'to'
  },
  localization: {
    localized: 'from',
    location: 'to'
  },
  drops: {
    dropping: 'from',
    dropped: 'to'
  },
  gathering: {
    part_of: 'from',
    gather: 'to'
  },
  // endregion
  // region stix_observable_relation
  linked: {
    link_from: 'from',
    link_to: 'to'
  },
  resolves: {
    resolving: 'from',
    resolved: 'to'
  },
  belongs: {
    belonging_to: 'from',
    belonged_to: 'to'
  },
  corresponds: {
    correspond_from: 'from',
    correspond_to: 'to'
  },
  contains: {
    container: 'from',
    contained: 'to'
  }
  // endregion
};

export const isInversed = (relationType, fromRole) => {
  if (relationType && fromRole) {
    if (rolesMap[relationType]) {
      if (rolesMap[relationType][fromRole] === 'from') {
        return false;
      }
      if (rolesMap[relationType][fromRole] === 'to') {
        return true;
      }
    }
  }
  return false;
};
