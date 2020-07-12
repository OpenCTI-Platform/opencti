import { assoc, head, includes, isEmpty, map, pipe } from 'ramda';
import { FunctionalError } from '../config/errors';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CITY,
  ENTITY_TYPE_COUNTRY,
  ENTITY_TYPE_COURSE,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INTRUSION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_MARKING,
  ENTITY_TYPE_NOTE,
  ENTITY_TYPE_OPINION,
  ENTITY_TYPE_ORGA,
  ENTITY_TYPE_REGION,
  ENTITY_TYPE_REPORT,
  ENTITY_TYPE_SECTOR,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_USER,
  ENTITY_TYPE_VULN,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT,
  RELATION_OBJECT_MARKING,
  RELATION_SIGHTING_NEGATIVE,
  RELATION_SIGHTING_POSITIVE,
} from '../utils/idGenerator';

export const STIX_SPEC_VERSION = '2.1';
export const OBSERVABLE_TYPES = [
  'autonomous-system',
  'cryptographic-key',
  'cryptocurrency-wallet',
  'directory',
  'domain',
  'email-address',
  'email-subject',
  'file-name',
  'file-path',
  'file-md5',
  'file-sha1',
  'file-sha256',
  'hostname',
  'ipv4-addr',
  'ipv6-addr',
  'mac-addr',
  'mutex',
  'pdb-path',
  'process',
  'registry-key',
  'registry-key-value',
  'text',
  'url',
  'user-account',
  'user-agent',
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
  // eslint-disable-next-line no-restricted-syntax
  for (const [key, value] of Object.entries(associationMap)) {
    if (entityData[key] && isNotEmpty(entityData[key])) {
      finalData[value] = entityData[key];
    }
  }
  return finalData;
};

export const markingDefinitionsToStix = (markingDefinitionsEdges) =>
  map((markingDefinition) => markingDefinition.node.standard_stix_id, markingDefinitionsEdges);

export const externalReferencesToStix = (externalReferencesEdges) =>
  map(
    (externalReference) =>
      buildStixData({}, externalReference.node, { source_name: 'source_name', external_id: 'external_id', url: 'url' }),
    externalReferencesEdges
  );

export const labelsToStix = (labelsEdges) => map((label) => label.value, labelsEdges);

export const killChainPhasesToStix = (killChainPhasesEdges) =>
  map(
    (killChainPhase) =>
      buildStixData({}, killChainPhase.node, { kill_chain_name: 'kill_chain_name', phase_name: 'phase_name' }),
    killChainPhasesEdges
  );

export const objectRefsToStix = (objectRefsEdges) =>
  map((objectRef) => objectRef.node.standard_stix_id, objectRefsEdges);

export const markingDefinitionToStix = (markingDefinition, onlyBase = false) => {
  const baseData = {
    id: markingDefinition.standard_stix_id,
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
    id: attackPattern.standard_stix_id,
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
    id: campaign.standard_stix_id,
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
    id: courseOfAction.standard_stix_id,
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
    id: identity.standard_stix_id,
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
    id: incident.standard_stix_id,
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
    id: indicator.standard_stix_id,
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
    id: intrusionSet.standard_stix_id,
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
    id: malware.standard_stix_id,
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
    id: note.standard_stix_id,
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
    id: opinion.standard_stix_id,
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
    id: report.standard_stix_id,
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
    id: threatActor.standard_stix_id,
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
    id: tool.standard_stix_id,
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
    id: vulnerability.standard_stix_id,
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
    id: stixObservable.standard_stix_id,
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
    id: stixRelation.standard_stix_id,
    type: 'relationship',
    spec_version: STIX_SPEC_VERSION,
  };
  if (extra && extra.from && extra.to) {
    baseData = pipe(
      assoc('source_ref', extra.from.standard_stix_id),
      assoc('target_ref', extra.to.standard_stix_id),
    )(baseData);
  }
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, stixRelation, {
    entity_type: 'entity_type',
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

export const stixSightingToStix = async (stixRelation, extra = null, onlyBase = true) => {
  let baseData = {
    id: stixRelation.standard_stix_id,
    type: 'sighting',
    spec_version: STIX_SPEC_VERSION,
  };
  if (extra && extra.from && extra.to) {
    baseData = pipe(
      assoc('sighting_of_ref', extra.from.standard_stix_id),
      assoc('where_sighted_refs', [extra.to.standard_stix_id])
    )(baseData);
  }
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, stixRelation, {
    confidence: 'confidence',
    description: 'description',
    sighting_of_ref: 'sighting_of_ref',
    where_sighted_refs: 'where_sighted_refs',
    revoked: 'revoked',
    created: 'created',
    modified: 'modified',
    first_seen: 'x_opencti_first_seen',
    last_seen: 'x_opencti_last_seen',
    negative: 'x_opencti_false_positive',
  });
};

export const relationEmbeddedToStix = async (relationEmbedded, eventType, extra) => {
  let entityType = extra.from.entity_type;
  if (includes(entityType, IDENTITY_TYPES)) {
    entityType = 'identity';
  }
  let data = {
    id: extra.from.standard_stix_id,
    type: entityType,
    spec_version: STIX_SPEC_VERSION,
  };
  if (relationEmbedded.entity_type === RELATION_CREATED_BY) {
    data = assoc(RELATION_CREATED_BY, extra.to ? extra.to.standard_stix_id : null, data);
  } else if (relationEmbedded.entity_type === RELATION_OBJECT_MARKING) {
    data = assoc(RELATION_OBJECT_MARKING, markingDefinitionsToStix([{ node: extra.to }]), data);
  } else if (relationEmbedded.entity_type === RELATION_EXTERNAL_REFERENCE) {
    data = assoc(RELATION_EXTERNAL_REFERENCE, externalReferencesToStix([{ node: extra.to }]), data);
  } else if (relationEmbedded.entity_type === RELATION_KILL_CHAIN_PHASE) {
    data = assoc(RELATION_KILL_CHAIN_PHASE, killChainPhasesToStix([{ node: extra.to }]), data);
  } else if (relationEmbedded.entity_type === RELATION_OBJECT) {
    data = assoc(RELATION_OBJECT, objectRefsToStix([{ node: extra.to }]), data);
  } else if (relationEmbedded.entity_type === RELATION_OBJECT_LABEL) {
    data = assoc('labels', labelsToStix([{ node: extra.to }]), data);
  }
  return data;
};

export const convertDataToStix = async (data, eventType = null, eventExtraData = null) => {
  if (!data) {
    /* istanbul ignore next */
    throw FunctionalError('No data provided to STIX converter');
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
    case ENTITY_TYPE_MARKING:
      return markingDefinitionToStix(data, onlyBase);
    case ENTITY_TYPE_ATTACK_PATTERN:
      return attackPatternToStix(data, onlyBase);
    case ENTITY_TYPE_CAMPAIGN:
      return campaignToStix(data, onlyBase);
    case ENTITY_TYPE_COURSE:
      return courseOfActionToStix(data, onlyBase);
    case ENTITY_TYPE_CITY:
    case ENTITY_TYPE_COUNTRY:
    case ENTITY_TYPE_USER:
    case ENTITY_TYPE_ORGA:
    case ENTITY_TYPE_REGION:
    case ENTITY_TYPE_SECTOR:
      return identityToStix(data, onlyBase);
    case ENTITY_TYPE_INCIDENT:
      return incidentToStix(data, onlyBase);
    case ENTITY_TYPE_INDICATOR:
      return indicatorToStix(data, onlyBase);
    case ENTITY_TYPE_INTRUSION:
      return intrusionSetToStix(data, onlyBase);
    case ENTITY_TYPE_MALWARE:
      return malwareToStix(data, onlyBase);
    case ENTITY_TYPE_NOTE:
      return noteToStix(data, onlyBase);
    case ENTITY_TYPE_OPINION:
      return opinionToStix(data, onlyBase);
    case ENTITY_TYPE_REPORT:
      return reportToStix(data, onlyBase);
    case ENTITY_TYPE_THREAT_ACTOR:
      return threatActorToStix(data, onlyBase);
    case ENTITY_TYPE_TOOL:
      return toolToStix(data, onlyBase);
    case ENTITY_TYPE_VULN:
      return vulnerabilityToStix(data, onlyBase);
    case 'stix_observable':
      return stixObservableToStix(data, onlyBase);
    case 'stix_relation':
      return stixRelationToStix(data, eventExtraData, onlyBase);
    case RELATION_SIGHTING_NEGATIVE:
    case RELATION_SIGHTING_POSITIVE:
      return stixSightingToStix(data, eventExtraData, onlyBase);
    case 'relation_embedded':
      return relationEmbeddedToStix(data, eventType, eventExtraData);
    /* istanbul ignore next */
    default:
      /* istanbul ignore next */
      throw FunctionalError(`Entity type ${entityType} is unknown, cannot convert to STIX`);
  }
};
