import { head, includes, last, mapObjIndexed, pipe, values } from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import moment from 'moment';

export const INDEX_STIX_OBSERVABLE = 'stix_observables';
export const INDEX_STIX_ENTITIES = 'stix_domain_entities_v2';
export const INDEX_STIX_RELATIONS = 'stix_relations';

export const TYPE_OPENCTI_INTERNAL = 'Internal';
export const TYPE_STIX_DOMAIN_ENTITY = 'Stix-Domain-Entity';
export const TYPE_STIX_OBSERVABLE = 'Stix-Observable';
export const TYPE_STIX_RELATION = 'stix_relation';
export const TYPE_STIX_OBSERVABLE_RELATION = 'stix_observable_relation';
export const TYPE_RELATION_EMBEDDED = 'relation_embedded';
export const TYPE_STIX_RELATION_EMBEDDED = 'stix_relation_embedded';

export const utcDate = (date = undefined) => (date ? moment(date).utc() : moment().utc());

export const fillTimeSeries = (startDate, endDate, interval, data) => {
  const startDateParsed = moment(startDate);
  const endDateParsed = moment(endDate);
  let dateFormat;

  switch (interval) {
    case 'year':
      dateFormat = 'YYYY';
      break;
    case 'month':
      dateFormat = 'YYYY-MM';
      break;
    default:
      dateFormat = 'YYYY-MM-DD';
  }

  const elementsOfInterval = endDateParsed.diff(startDateParsed, `${interval}s`, false);

  const newData = [];
  for (let i = 0; i <= elementsOfInterval; i += 1) {
    const workDate = moment(startDateParsed).add(i, `${interval}s`);

    // Looking for the value
    let dataValue = 0;
    for (let j = 0; j < data.length; j += 1) {
      if (data[j].date === workDate.format(dateFormat)) {
        dataValue = data[j].value;
      }
    }
    const intervalDate = moment(workDate)
      .startOf(interval)
      .utc()
      .toISOString();
    newData[i] = {
      date: intervalDate,
      value: dataValue
    };
  }
  return newData;
};

export const buildPagination = (first, offset, instances, globalCount) => {
  const edges = pipe(
    mapObjIndexed((record, key) => {
      const { node } = record;
      const { relation } = record;
      const nodeOffset = offset + parseInt(key, 10) + 1;
      return { node, relation, cursor: offsetToCursor(nodeOffset) };
    }),
    values
  )(instances);
  const hasNextPage = first + offset < globalCount;
  const hasPreviousPage = offset > 0;
  const startCursor = edges.length > 0 ? head(edges).cursor : '';
  const endCursor = edges.length > 0 ? last(edges).cursor : '';
  const pageInfo = {
    startCursor,
    endCursor,
    hasNextPage,
    hasPreviousPage,
    globalCount
  };
  return { edges, pageInfo };
};

export const inferIndexFromConceptTypes = (types, parentType = null) => {
  // Observable index
  if (includes(TYPE_STIX_OBSERVABLE, types) || parentType === TYPE_STIX_OBSERVABLE) return INDEX_STIX_OBSERVABLE;
  // Relation index
  if (includes(TYPE_STIX_RELATION, types) || parentType === TYPE_STIX_RELATION) return INDEX_STIX_RELATIONS;
  if (includes(TYPE_STIX_OBSERVABLE_RELATION, types) || parentType === TYPE_STIX_OBSERVABLE_RELATION)
    return INDEX_STIX_RELATIONS;
  if (includes(TYPE_STIX_RELATION_EMBEDDED, types) || parentType === TYPE_STIX_RELATION_EMBEDDED)
    return INDEX_STIX_RELATIONS;
  if (includes(TYPE_RELATION_EMBEDDED, types) || parentType === TYPE_RELATION_EMBEDDED) return INDEX_STIX_RELATIONS;
  // Everything else in entities index
  return INDEX_STIX_ENTITIES;
};
