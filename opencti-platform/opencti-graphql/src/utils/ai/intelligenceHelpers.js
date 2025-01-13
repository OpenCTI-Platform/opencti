import { distributionRelations, timeSeriesEntities } from '../../database/middleware';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_RELATIONSHIP } from '../../schema/general';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { ENTITY_TYPE_HISTORY } from '../../schema/internalObject';
import { listEntities } from '../../database/middleware-loader';

export const systemPrompt = `You are a threat intelligence analyst and your role is to help analyzing numbers and statistics about the activity and the context of cyber entities.". 
# General instructions
- 
- The provided data is private data coming from an OpenCTI instance.
- The summary should be based on the context and the statistics.
- The summary should be formatted in HTML and highlight important numbers with appropriate colors and bold if necessary.
- The returned answer should be only the summary and nothing else.
- The returned answer should not contain any generic assumptions or recommendations, it should rely only on the given context and statistics.

# Reporting instructions
- The output summary 
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
