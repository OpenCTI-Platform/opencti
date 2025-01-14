import * as R from 'ramda';
import { distributionRelations, timeSeriesEntities, timeSeriesRelations } from '../../database/middleware';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  ENTITY_TYPE_CONTAINER,
  ENTITY_TYPE_IDENTITY,
  ENTITY_TYPE_LOCATION,
  ENTITY_TYPE_THREAT_ACTOR
} from '../../schema/general';
import { extractEntityRepresentativeName, extractRepresentativeDescription } from '../../database/entity-representative';
import { listAllToEntitiesThroughRelations } from '../../database/middleware-loader';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import {
  RELATION_AMPLIFIES,
  RELATION_ATTRIBUTED_TO,
  RELATION_COMPROMISES,
  RELATION_COOPERATES_WITH,
  RELATION_HAS,
  RELATION_INDICATES,
  RELATION_LOCATED_AT,
  RELATION_TARGETS,
  RELATION_USES
} from '../../schema/stixCoreRelationship';
import { isNotEmptyField, READ_INDEX_HISTORY } from '../../database/utils';
import { FROM_START_STR, UNTIL_END_STR } from '../format';
import { paginatedForPathWithEnrichment } from '../../modules/internal/document/document-domain';
import { elSearchFiles } from '../../database/file-search';
import { elPaginate } from '../../database/engine';
import { ENTITY_TYPE_HISTORY } from '../../schema/internalObject';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_INDICATOR } from '../../modules/indicator/indicator-types';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INCIDENT, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../../modules/threatActorIndividual/threatActorIndividual-types';

export const RESOLUTION_LIMIT = 200;
export const systemPrompt = `
- You are a cyber threat intelligence analyst and your role is to help analyzing numbers and statistics about the activity and the context of cyber entities. 
- You are always analysing data coming from an OpenCTI instance.
- You should avoid using your general knowledge to answer questions and focus on the data provided by the user. 
`;

export const getContainersStats = async (context, user, id, startDate, endDate) => {
  const filters = { mode: 'and',
    filters: [
      { key: 'entity_type', values: [ENTITY_TYPE_CONTAINER] },
      { key: 'objects', values: [id] }
    ],
    filterGroups: []
  };
  return timeSeriesEntities(context, user, [ABSTRACT_STIX_DOMAIN_OBJECT], {
    field: 'created',
    startDate,
    endDate,
    interval: 'month',
    filters
  });
};

export const getIndicatorsStats = async (context, user, id, startDate, endDate) => {
  const filters = { mode: 'and',
    filters: [
      { key: 'entity_type', values: [ENTITY_TYPE_INDICATOR] },
      { key: 'regardingOf',
        values: [
          { key: 'relationship_type', values: [RELATION_INDICATES] },
          { key: 'id', values: [id] }
        ],
      },
    ],
    filterGroups: []
  };
  return timeSeriesEntities(context, user, [ABSTRACT_STIX_DOMAIN_OBJECT], {
    field: 'created',
    startDate,
    endDate,
    interval: 'month',
    filters
  });
};

export const getVictimologyStats = async (context, user, id, startDate, endDate) => {
  const filters = {
    mode: 'and',
    filters: [
      { key: 'relationship_type', values: [RELATION_TARGETS] },
      { key: 'fromId', values: [id] },
      { key: 'toTypes', values: [ENTITY_TYPE_LOCATION, ENTITY_TYPE_IDENTITY] },
    ],
    filterGroups: []
  };
  return timeSeriesRelations(context, user, {
    field: 'created',
    startDate,
    endDate,
    interval: 'month',
    filters
  });
};

export const getTopThreats = async (context, user, id, types, startDate, endDate) => {
  const filters = {
    mode: 'and',
    filters: [
      { key: 'relationship_type', values: [RELATION_TARGETS] },
      { key: 'fromTypes', values: types },
      { key: 'toId', values: [id] },
    ],
    filterGroups: []
  };
  const distribution = await distributionRelations(context, user, {
    relationship_type: [ABSTRACT_STIX_RELATIONSHIP],
    field: 'internal_id',
    isTo: true,
    limit: 20,
    dateAttribute: 'created',
    operation: 'count',
    filters,
    startDate,
    endDate
  });
  return distribution.map((n) => ({ label: extractEntityRepresentativeName(n.entity), value: n.value }));
};

export const getTopVictims = async (context, user, id, types, startDate, endDate) => {
  const filters = {
    mode: 'and',
    filters: [
      { key: 'relationship_type', values: [RELATION_TARGETS] },
      { key: 'fromId', values: [id] },
      { key: 'toTypes', values: types },
    ],
    filterGroups: []
  };
  const distribution = await distributionRelations(context, user, {
    relationship_type: [ABSTRACT_STIX_RELATIONSHIP],
    field: 'internal_id',
    isTo: true,
    limit: 20,
    dateAttribute: 'created',
    operation: 'count',
    filters,
    startDate,
    endDate
  });
  return distribution.map((n) => ({ label: extractEntityRepresentativeName(n.entity), value: n.value }));
};

export const getTargetingStats = async (context, user, id, startDate, endDate) => {
  const filters = {
    mode: 'and',
    filters: [
      { key: 'relationship_type', values: [RELATION_TARGETS] },
      { key: 'fromTypes',
        values: [
          ENTITY_TYPE_THREAT_ACTOR_GROUP,
          ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
          ENTITY_TYPE_INTRUSION_SET,
          ENTITY_TYPE_INTRUSION_SET,
          ENTITY_TYPE_CAMPAIGN,
          ENTITY_TYPE_INCIDENT,
          ENTITY_TYPE_MALWARE,
        ] },
      { key: 'toId', values: [id] },
    ],
    filterGroups: []
  };
  return timeSeriesRelations(context, user, {
    field: 'created',
    startDate,
    endDate,
    interval: 'month',
    filters
  });
};

export const getHistory = (context, user, id) => {
  const filters = {
    mode: 'and',
    filterGroups: [],
    filters: [
      { key: 'context_data.id', values: [id] },
      {
        key: 'event_type',
        values: [
          'mutation',
          'create',
          'update',
          'delete',
          'merge'
        ]
      }
    ]
  };
  const args = { types: [ENTITY_TYPE_HISTORY], filters, first: 200, orderBy: 'timestamp', orderMode: 'desc', connectionFormat: false };
  return elPaginate(context, user, READ_INDEX_HISTORY, args);
};

export const getContainerKnowledge = async (context, user, id) => {
  const elements = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT, [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP]);
  // generate mappings
  const relationships = R.take(RESOLUTION_LIMIT, elements.filter((n) => n.parent_types.includes(ABSTRACT_STIX_CORE_RELATIONSHIP)));
  const entities = R.take(RESOLUTION_LIMIT, elements.filter((n) => !isStixCyberObservable(n.entity_type) && n.entity_type !== ENTITY_TYPE_INDICATOR));
  const indexedEntities = R.indexBy(R.prop('id'), entities);

  // generate entities involved
  const entitiesInvolved = R.values(indexedEntities).map((n) => {
    return `
      -------------------
      - The ${n.entity_type} ${extractEntityRepresentativeName(n)} described / detailed with the description: ${extractRepresentativeDescription(n)}.
      -------------------
    `;
  });
  // generate relationships sentences
  const meaningfulRelationships = [
    RELATION_TARGETS,
    RELATION_USES,
    RELATION_ATTRIBUTED_TO,
    RELATION_AMPLIFIES,
    RELATION_COMPROMISES,
    RELATION_COOPERATES_WITH,
    RELATION_LOCATED_AT,
    RELATION_HAS
  ];
  const relationshipsSentences = relationships.filter((n) => meaningfulRelationships.includes(n.relationship_type)).map((n) => {
    const from = indexedEntities[n.fromId];
    const to = indexedEntities[n.toId];
    if (isNotEmptyField(from) && isNotEmptyField(to)) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      const startTime = n.start_time === FROM_START_STR ? 'unknown date' : n.start_time;
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      const stopTime = n.stop_time === UNTIL_END_STR ? 'unknown date' : n.stop_time;
      return `
        -------------------
      - The ${from} ${extractEntityRepresentativeName(from)} ${n.relationship_type} the ${to.entity_type} ${extractEntityRepresentativeName(to)} from ${startTime} to ${stopTime} (${n.description}).
        -------------------
      `;
    }
    return '';
  });
  return { relationshipsSentences: relationshipsSentences.join(''), entitiesInvolved: entitiesInvolved.join('') };
};

export const resolveFiles = async (context, user, stixCoreObject) => {
  const opts = {
    first: 1,
    prefixMimeTypes: undefined,
    entity_id: stixCoreObject.id,
    entity_type: stixCoreObject.entity_type
  };
  const importFiles = await paginatedForPathWithEnrichment(context, user, `import/${stixCoreObject.entity_type}/${stixCoreObject.id}`, stixCoreObject.id, opts);
  const fileIds = importFiles.edges.map((n) => n.node.id);
  if (fileIds.length === 0) {
    return [];
  }
  const files = await elSearchFiles(context, user, {
    first: 1,
    fileIds,
    connectionFormat: false,
    excludeFields: [],
    includeContent: true
  });
  return files;
};
