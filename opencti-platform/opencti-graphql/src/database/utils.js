import { head, last, mapObjIndexed, pipe, values, join } from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import moment from 'moment';
import {
  isInternalObject,
  isInternalRelationship, isObservableRelation,
  isStixCoreObject,
  isStixCyberObservable,
  isStixRelation,
} from '../utils/idGenerator';
import { DatabaseError } from '../config/errors';

export const INDEX_STIX_OBSERVABLE = 'opencti_stix_observables';
export const INDEX_STIX_ENTITIES = 'opencti_stix_entities';
export const INDEX_STIX_RELATIONS = 'opencti_stix_relations';
export const INDEX_INTERNAL_ENTITIES = 'opencti_internal_entities';
export const INDEX_INTERNAL_RELATIONS = 'opencti_internal_relations';

export const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const utcDate = (date = undefined) => (date ? moment(date).utc() : moment().utc());

export const fillTimeSeries = (startDate, endDate, interval, data) => {
  const startDateParsed = moment.parseZone(startDate);
  const endDateParsed = moment.parseZone(endDate);
  let dateFormat;

  switch (interval) {
    case 'year':
      dateFormat = 'YYYY';
      break;
    case 'month':
      dateFormat = 'YYYY-MM';
      break;
    /* istanbul ignore next */
    default:
      dateFormat = 'YYYY-MM-DD';
  }

  const startFormatDate = new Date(endDateParsed.format(dateFormat));
  const endFormatDate = new Date(startDateParsed.format(dateFormat));
  const elementsOfInterval = moment(startFormatDate).diff(moment(endFormatDate), `${interval}s`);
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
    const intervalDate = moment(workDate).startOf(interval).utc().toISOString();
    newData[i] = {
      date: intervalDate,
      value: dataValue,
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
    globalCount,
  };
  return { edges, pageInfo };
};

export const inferIndexFromConceptType = (conceptType) => {
  // Entities
  if (isStixCoreObject(conceptType)) return INDEX_STIX_ENTITIES;
  if (isStixCyberObservable(conceptType)) return INDEX_STIX_OBSERVABLE;
  if (isInternalObject(conceptType)) return INDEX_INTERNAL_ENTITIES;
  // Relations
  if (isStixRelation(conceptType)) return INDEX_STIX_RELATIONS;
  if (isObservableRelation(conceptType)) return INDEX_STIX_RELATIONS;
  if (isInternalRelationship(conceptType)) return INDEX_INTERNAL_RELATIONS;
  throw DatabaseError(`Cant find index for type ${conceptType}`);
};

export const isIndexable = (type) => {
  return inferIndexFromConceptType(type) !== null;
};

const extractEntityMainValue = (entityData) => {
  let mainValue;
  if (entityData.definition) {
    mainValue = entityData.definition;
  } else if (entityData.value) {
    mainValue = entityData.value;
  } else if (entityData.observable_value) {
    mainValue = entityData.observable_value;
  } else if (entityData.indicator_pattern) {
    mainValue = entityData.indicator_pattern;
  } else if (entityData.source_name) {
    mainValue = `${entityData.source_name}${entityData.external_id ? ` (${entityData.external_id})` : ''}`;
  } else if (entityData.phase_name) {
    mainValue = entityData.phase_name;
  } else if (entityData.name) {
    mainValue = entityData.name;
  } else {
    mainValue = entityData.description;
  }
  return mainValue;
};

export const generateLogMessage = (eventType, eventUser, eventData, eventExtraData) => {
  let fromValue;
  let fromType;
  let toValue;
  let toType;
  let toRelationType;
  if (eventExtraData && eventExtraData.from) {
    fromValue = extractEntityMainValue(eventExtraData.from);
    fromType = eventExtraData.from.entity_type;
  }
  if (eventExtraData && eventExtraData.to) {
    toValue = extractEntityMainValue(eventExtraData.to);
    toType = eventExtraData.to.entity_type;
    toRelationType = eventExtraData.to.entity_type;
  }
  const name = extractEntityMainValue(eventData);
  let message = '';
  if (eventType === 'create') {
    message += 'created a ';
  } else if (eventType === 'update') {
    message += 'updated the field ';
  } else if (eventType === 'update_add') {
    message += 'added the ';
  } else if (eventType === 'update_remove') {
    message += 'removed the ';
  } else if (eventType === 'delete') {
    message += 'deleted the ';
  }
  if (isStixRelation(eventData.entity_type)) {
    message += `relation \`${eventData.entity_type}\` from ${fromType} \`${fromValue}\` to ${toType} \`${toValue}\`.`;
  } else if (isInternalRelationship(eventData.entity_type)) {
    if (eventType === 'update') {
      message += `\`${eventData.entity_type}\` with the value \`${toValue}\`.`;
    } else if (toType === 'stix_relation') {
      message += `relation \`${toRelationType}\`${toValue ? `with value \`${toValue}\`` : ''}.`;
    } else {
      message += `\`${toType}\` with value \`${toValue}\`.`;
    }
  } else if (eventType === 'update') {
    message += `\`${eventExtraData.key}\` with \`${join(', ', eventExtraData.value)}\`.`;
  } else {
    message += `${eventData.entity_type} \`${name}\`.`;
  }
  return message;
};
