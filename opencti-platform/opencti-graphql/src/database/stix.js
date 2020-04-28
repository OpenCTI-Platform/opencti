import { pipe, includes, isEmpty, head, assoc, map } from 'ramda';

export const STIX_SPEC_VERSION = '2.1';
export const OBSERVABLE_TYPES = [
  'autonomous-system',
  'directory',
  'domain',
  'email-address',
  'email-subject',
  'file-name',
  'file-path',
  'file-md5',
  'file-sha1',
  'file-sha256',
  'ipv4-addr',
  'ipv6-addr',
  'mac-addr',
  'mutex',
  'pdb-path',
  'registry-key',
  'registry-key-value',
  'url',
  'windows-service-name',
  'windows-service-display-name',
  'windows-scheduled-task',
  'x509-certificate-issuer',
  'x509-certificate-serial-number',
  'unknown',
];
export const IDENTITY_TYPES = ['sector', 'user', 'organization', 'city', 'country', 'region'];

const isNotEmpty = (value) => {
  if (isEmpty(value)) {
    return false;
  }
  return !(Array.isArray(value) && head(value).length === 0);
};

export const buildStixData = (baseData, entityData, associationMap) => {
  const finalData = baseData;
  for (const [key, value] of Object.entries(associationMap)) {
    if (entityData[key] && isNotEmpty(entityData[key])) {
      finalData[value] = entityData[key];
    }
  }
  return finalData;
};

export const markingDefinitionsToStix = (markingDefinitionsEdges) =>
  map((markingDefinition) => markingDefinition.node.stix_id_key, markingDefinitionsEdges);

export const externalReferencesToStix = (externalReferencesEdges) =>
  map(
    (externalReference) =>
      buildStixData({}, externalReference.node, { source_name: 'source_name', external_id: 'external_id', url: 'url' }),
    externalReferencesEdges
  );

export const tagsToStix = (tagsEdges) =>
  map((tag) => buildStixData({}, tag.node, { tag_type: 'tag_type', value: 'value', color: 'color' }), tagsEdges);

export const killChainPhasesToStix = (killChainPhasesEdges) =>
  map(
    (killChainPhase) =>
      buildStixData({}, killChainPhase.node, { kill_chain_name: 'kill_chain_name', phase_name: 'phase_name' }),
    killChainPhasesEdges
  );

export const objectRefsToStix = (objectRefsEdges) => map((objectRef) => objectRef.node.stix_id_key, objectRefsEdges);

export const markingDefinitionToStix = (markingDefinition, onlyBase = false) => {
  const baseData = {
    id: markingDefinition.stix_id_key,
    x_opencti_id: markingDefinition.id,
    type: 'marking-definition',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, markingDefinition, {
    definition_type: 'definition_type',
    definition: 'definition',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'x_opencti_modified',
  });
};

export const attackPatternToStix = (attackPattern, onlyBase = false) => {
  const baseData = {
    id: attackPattern.stix_id_key,
    x_opencti_id: attackPattern.id,
    type: 'attack-pattern',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, attackPattern, {
    name: 'name',
    alias: 'aliases',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    platform: 'x_mitre_platforms',
    required_permission: 'x_mitre_permissions_required',
  });
};

export const campaignToStix = async (campaign, onlyBase = false) => {
  const baseData = {
    id: campaign.stix_id_key,
    x_opencti_id: campaign.id,
    type: 'campaign',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, campaign, {
    name: 'name',
    aliases: 'aliases',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    objective: 'objective',
    first_seen: 'x_opencti_first_seen',
    last_seen: 'x_opencti_last_seen',
  });
};

export const courseOfActionToStix = async (courseOfAction, onlyBase = false) => {
  const baseData = {
    id: courseOfAction.stix_id_key,
    x_opencti_id: courseOfAction.id,
    type: 'course-of-action',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, courseOfAction, {
    name: 'name',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    alias: 'x_opencti_aliases',
  });
};

export const identityToStix = async (identity, onlyBase = false) => {
  let identityClass = 'organization';
  if (identity.entity_type === 'user') {
    identityClass = 'individual';
  } else if (identity.entity_type === 'sector') {
    identityClass = 'class';
  }
  const baseData = {
    id: identity.stix_id_key,
    x_opencti_id: identity.id,
    type: 'identity',
    spec_version: STIX_SPEC_VERSION,
    identity_class: identityClass,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, identity, {
    name: 'name',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    entity_type: 'x_opencti_identity_type',
    alias: 'x_opencti_aliases',
  });
};

export const incidentToStix = async (incident, onlyBase = false) => {
  const baseData = {
    id: incident.stix_id_key,
    x_opencti_id: incident.id,
    type: 'x-opencti-incident',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, incident, {
    name: 'name',
    alias: 'aliases',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    objective: 'objective',
    first_seen: 'first_seen',
    last_seen: 'last_seen',
  });
};

export const indicatorToStix = async (indicator, onlyBase = false) => {
  const baseData = {
    id: indicator.stix_id_key,
    x_opencti_id: indicator.id,
    type: 'indicator',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, indicator, {
    name: 'name',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    pattern_type: 'pattern_type',
    indicator_pattern: 'pattern',
    valid_from: 'valid_from',
    valid_until: 'valid_until',
    alias: 'x_opencti_aliases',
  });
};

export const intrusionSetToStix = async (intrusionSet, onlyBase = false) => {
  const baseData = {
    id: intrusionSet.stix_id_key,
    x_opencti_id: intrusionSet.id,
    type: 'intrusion-set',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, intrusionSet, {
    name: 'name',
    alias: 'aliases',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    goal: 'goals',
    sophistication: 'sophistication',
    resource_level: 'resource_level',
    primary_motivation: 'primary_motivation',
    secondary_motivation: 'secondary_motivations',
    first_seen: 'x_opencti_first_seen',
    last_seen: 'x_opencti_last_seen',
  });
};

export const malwareToStix = async (malware, onlyBase = false) => {
  const baseData = {
    id: malware.stix_id_key,
    x_opencti_id: malware.id,
    type: 'malware',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, malware, {
    name: 'name',
    alias: 'aliases',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
  });
};

export const noteToStix = async (note, onlyBase = false) => {
  const baseData = {
    id: note.stix_id_key,
    x_opencti_id: note.id,
    type: 'note',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, note, {
    description: 'abstract',
    content: 'content',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    name: 'x_opencti_name',
    alias: 'x_opencti_aliases',
    graph_data: 'x_opencti_graph_data',
  });
};

export const opinionToStix = async (opinion, onlyBase = false) => {
  const baseData = {
    id: opinion.stix_id_key,
    x_opencti_id: opinion.id,
    type: 'opinion',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, opinion, {
    explanation: 'explanation',
    description: 'opinion',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    name: 'x_opencti_name',
    alias: 'x_opencti_aliases',
    graph_data: 'x_opencti_graph_data',
  });
};

export const reportToStix = async (report, onlyBase = false) => {
  const baseData = {
    id: report.stix_id_key,
    x_opencti_id: report.id,
    type: 'report',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, report, {
    name: 'name',
    description: 'description',
    published: 'published',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    report_class: 'x_opencti_report_class',
    object_status: 'x_opencti_object_status',
    source_confidence_level: 'x_opencti_source_confidence_level',
    alias: 'x_opencti_aliases',
    graph_data: 'x_opencti_graph_data',
  });
};

export const threatActorToStix = async (threatActor, onlyBase = false) => {
  const baseData = {
    id: threatActor.stix_id_key,
    x_opencti_id: threatActor.id,
    type: 'threat-actor',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, threatActor, {
    name: 'name',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    sophistication: 'sophistication',
    resource_level: 'resource_level',
    primary_motivation: 'primary_motivation',
    secondary_motivation: 'secondary_motivations',
    first_seen: 'x_opencti_first_seen',
    last_seen: 'x_opencti_last_seen',
    alias: 'x_opencti_aliases',
  });
};

export const toolToStix = async (tool, onlyBase = false) => {
  const baseData = {
    id: tool.stix_id_key,
    x_opencti_id: tool.id,
    type: 'tool',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, tool, {
    name: 'name',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    tool_version: 'tool_version',
    tool_types: 'tool_types',
    alias: 'x_opencti_aliases',
  });
};

export const vulnerabilityToStix = async (vulnerability, onlyBase = false) => {
  const baseData = {
    id: vulnerability.stix_id_key,
    x_opencti_id: vulnerability.id,
    type: 'vulnerability',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, vulnerability, {
    name: 'name',
    description: 'description',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
  });
};

export const stixObservableToStix = async (stixObservable, onlyBase = false) => {
  const baseData = {
    id: stixObservable.stix_id_key,
    x_opencti_id: stixObservable.id,
    type: stixObservable.entity_type,
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, stixObservable, {
    entity_type: 'x_opencti_observable_type',
    observable_value: 'x_opencti_observable_value',
  });
};

export const stixRelationToStix = async (stixRelation, extra = null, onlyBase = true) => {
  let baseData = {
    id: stixRelation.stix_id_key,
    x_opencti_id: stixRelation.id,
    type: 'relationship',
    spec_version: STIX_SPEC_VERSION,
  };
  if (extra && extra.from && extra.to) {
    baseData = pipe(
      assoc('source_ref', extra.from.stix_id_key),
      assoc('x_opencti_source_ref', extra.from.internal_id_key),
      assoc('target_ref', extra.to.stix_id_key),
      assoc('x_opencti_target_ref', extra.to.internal_id_key)
    )(baseData);
  }
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, stixRelation, {
    relationship_type: 'relationship_type',
    description: 'description',
    source_ref: 'source_ref',
    target_ref: 'target_ref',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    first_seen: 'x_opencti_first_seen',
    last_seen: 'x_opencti_last_seen',
    weight: 'x_opencti_weight',
    role_played: 'x_opencti_role_played',
  });
};

export const relationEmbeddedToStix = async (relationEmbedded, eventType, extra) => {
  let entityType = extra.from.entity_type;
  if (includes(entityType, IDENTITY_TYPES)) {
    entityType = 'identity';
  }
  let data = {
    id: extra.from.stix_id_key,
    x_opencti_id: extra.from.id,
    type: entityType,
    spec_version: STIX_SPEC_VERSION,
  };
  if (relationEmbedded.relationship_type === 'created_by_ref') {
    data = assoc('created_by_ref', extra.to.stix_id_key, data);
  } else if (relationEmbedded.relationship_type === 'object_marking_refs') {
    data = assoc('object_marking_refs', markingDefinitionsToStix([{ node: extra.to }]), data);
  } else if (relationEmbedded.relationship_type === 'external_references') {
    data = assoc('external_references', externalReferencesToStix([{ node: extra.to }]), data);
  } else if (relationEmbedded.relationship_type === 'kill_chain_phases') {
    data = assoc('kill_chain_phases', killChainPhasesToStix([{ node: extra.to }]), data);
  } else if (relationEmbedded.relationship_type === 'object_refs') {
    data = assoc('object_refs', objectRefsToStix([{ node: extra.to }]), data);
  } else if (relationEmbedded.relationship_type === 'observable_refs') {
    data = assoc('object_refs', objectRefsToStix([{ node: extra.to }]), data);
  } else if (relationEmbedded.relationship_type === 'relation_refs') {
    data = assoc('object_refs', objectRefsToStix([{ node: extra.to }]), data);
  } else if (relationEmbedded.relationship_type === 'tagged') {
    data = assoc('x_opencti_tags', tagsToStix([{ node: extra.to }]), data);
  }
  return data;
};

export const convertDataToStix = async (data, eventType = null, eventExtraData = null) => {
  if (!data) {
    /* istanbul ignore next */
    throw new Error('[STIX] No eventData provided');
  }
  let entityType = data.entity_type;
  if (includes(entityType, IDENTITY_TYPES)) {
    entityType = 'identity';
  }
  if (includes(entityType, OBSERVABLE_TYPES)) {
    entityType = 'stix_observable';
  }
  const onlyBase = eventType === 'delete';
  switch (entityType) {
    case 'marking-definition':
      return markingDefinitionToStix(data, onlyBase);
    case 'attack-pattern':
      return attackPatternToStix(data, onlyBase);
    case 'campaign':
      return campaignToStix(data, onlyBase);
    case 'course-of-action':
      return courseOfActionToStix(data, onlyBase);
    case 'identity':
      return identityToStix(data, onlyBase);
    case 'incident':
      return incidentToStix(data, onlyBase);
    case 'indicator':
      return indicatorToStix(data, onlyBase);
    case 'intrusion-set':
      return intrusionSetToStix(data, onlyBase);
    case 'malware':
      return malwareToStix(data, onlyBase);
    case 'note':
      return noteToStix(data, onlyBase);
    case 'opinion':
      return opinionToStix(data, onlyBase);
    case 'report':
      return reportToStix(data, onlyBase);
    case 'threat-actor':
      return threatActorToStix(data, onlyBase);
    case 'tool':
      return toolToStix(data, onlyBase);
    case 'vulnerability':
      return vulnerabilityToStix(data, onlyBase);
    case 'stix_observable':
      return stixObservableToStix(data, onlyBase);
    case 'stix_relation':
      return stixRelationToStix(data, eventExtraData, onlyBase);
    case 'relation_embedded':
      return relationEmbeddedToStix(data, eventType, eventExtraData);
    default:
      /* istanbul ignore next */
      throw new Error('[STIX] Entity type is unknown, cannot convert to STIX');
  }
};
