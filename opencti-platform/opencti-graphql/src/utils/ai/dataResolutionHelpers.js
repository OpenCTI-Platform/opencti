import * as R from 'ramda';
import { distributionRelations, timeSeriesEntities } from '../../database/middleware';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_RELATIONSHIP } from '../../schema/general';
import { extractEntityRepresentativeName, extractRepresentativeDescription } from '../../database/entity-representative';
import { ENTITY_TYPE_HISTORY } from '../../schema/internalObject';
import { listAllToEntitiesThroughRelations, listEntities } from '../../database/middleware-loader';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import {
  RELATION_AMPLIFIES,
  RELATION_ATTRIBUTED_TO,
  RELATION_COMPROMISES,
  RELATION_COOPERATES_WITH,
  RELATION_HAS,
  RELATION_LOCATED_AT,
  RELATION_TARGETS,
  RELATION_USES
} from '../../schema/stixCoreRelationship';
import { isNotEmptyField } from '../../database/utils';
import { FROM_START_STR, UNTIL_END_STR } from '../format';
import { paginatedForPathWithEnrichment } from '../../modules/internal/document/document-domain';
import { elSearchFiles } from '../../database/file-search';

export const RESOLUTION_LIMIT = 200;
export const systemPrompt = `
- You are a cyber threat intelligence analyst and your role is to help analyzing numbers and statistics about the activity and the context of cyber entities. 
- You are always analysing data coming from an OpenCTI instance.
- You should avoid using your general knowledge to answer questions and focus on the data provided by the user. 
`;

export const getIndicatorsStats = async (context, user, id, startDate, endDate) => {
  const filters = { mode: 'and',
    filters: [
      { key: 'entity_type', values: ['Indicator'], operator: 'eq', mode: 'or' },
      { key: 'regardingOf',
        values: [
          { key: 'relationship_type', values: ['indicates'] },
          { key: 'id', values: [id] }
        ],
        operator: 'eq',
        mode: 'or'
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
      { key: 'entity_type', values: ['Location', 'Identity'], operator: 'eq', mode: 'or' },
      { key: 'regardingOf',
        values: [
          { key: 'relationship_type', values: ['targets'] },
          { key: 'id', values: [id] }
        ],
        operator: 'eq',
        mode: 'or'
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

export const getTopVictims = async (context, user, id, types, startDate, endDate) => {
  const filters = {
    mode: 'and',
    filters: [
      { key: 'relationship_type', values: ['targets'], operator: 'eq', mode: 'or' },
      { key: 'fromId', values: [id], operator: 'eq', mode: 'or' },
      { key: 'toTypes', values: types, operator: 'eq', mode: 'or' },
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
  const args = { filters, first: 200, orderBy: 'timestamp', orderMode: 'desc', connectionFormat: false };
  return listEntities(context, user, [ENTITY_TYPE_HISTORY], args);
};

export const getContainerKnowledge = async (context, user, id) => {
  const elements = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT, [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP]);
  // generate mappings
  const relationships = R.take(RESOLUTION_LIMIT, elements.filter((n) => n.parent_types.includes(ABSTRACT_STIX_CORE_RELATIONSHIP)));
  const entities = R.take(RESOLUTION_LIMIT, elements.filter((n) => n.parent_types.includes(ABSTRACT_STIX_CORE_OBJECT)));
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
