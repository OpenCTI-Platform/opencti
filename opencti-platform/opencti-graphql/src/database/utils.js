import { head, last, mapObjIndexed, pipe, values, join } from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import moment from 'moment';
import {
  isInternalObject,
  isInternalRelationship,
  isStixCyberObservable,
  isStixCoreRelationship,
  isStixRelationship,
  isStixObject,
  isStixCyberObservableRelationship,
  isStixMetaRelationship, isStixMetaObject, isStixDomainObject
} from "../utils/idGenerator";
import { DatabaseError } from '../config/errors';

// Entities
export const INDEX_INTERNAL_OBJECTS = 'opencti_internal_objects';
export const INDEX_STIX_META_OBJECTS = 'opencti_stix_meta_objects';
export const INDEX_STIX_DOMAIN_OBJECTS = 'opencti_stix_domain_objects';
export const INDEX_STIX_CYBER_OBSERVABLES = 'opencti_stix_cyber_observables';
// Relations
export const INDEX_INTERNAL_RELATIONSHIPS = 'opencti_internal_relationships';
export const INDEX_STIX_CORE_RELATIONSHIPS = 'opencti_stix_core_relationships';
export const INDEX_STIX_SIGHTING_RELATIONSHIPS = 'opencti_stix_sighting_relationships';
export const INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS = 'opencti_stix_cyber_observable_relationships';
export const INDEX_STIX_META_RELATIONSHIPS = 'opencti_stix_meta_relationships';

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
  if (isInternalObject(conceptType)) return INDEX_INTERNAL_OBJECTS;
  if (isStixMetaObject(conceptType)) return INDEX_STIX_META_OBJECTS;
  if (isStixDomainObject(conceptType)) return INDEX_STIX_DOMAIN_OBJECTS;
  if (isStixCyberObservable(conceptType)) return INDEX_STIX_CYBER_OBSERVABLES;
  // Relations
  if (isInternalRelationship(conceptType)) return INDEX_INTERNAL_RELATIONSHIPS;
  if (isStixCyberObservableRelationship(conceptType)) return INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS;
  if (isStixMetaRelationship(conceptType)) return INDEX_STIX_META_RELATIONSHIPS;
  if (isStixRelationship(conceptType)) return INDEX_STIX_RELATIONSHIPS;

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
  let torelationship_type;
  if (eventExtraData && eventExtraData.from) {
    fromValue = extractEntityMainValue(eventExtraData.from);
    fromType = eventExtraData.from.entity_type;
  }
  if (eventExtraData && eventExtraData.to) {
    toValue = extractEntityMainValue(eventExtraData.to);
    toType = eventExtraData.to.entity_type;
    torelationship_type = eventExtraData.to.entity_type;
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
  if (isStixCoreRelationship(eventData.entity_type)) {
    message += `relation \`${eventData.entity_type}\` from ${fromType} \`${fromValue}\` to ${toType} \`${toValue}\`.`;
  } else if (isInternalRelationship(eventData.entity_type)) {
    if (eventType === 'update') {
      message += `\`${eventData.entity_type}\` with the value \`${toValue}\`.`;
    } else if (toType === 'stix_relation') {
      message += `relation \`${torelationship_type}\`${toValue ? `with value \`${toValue}\`` : ''}.`;
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
