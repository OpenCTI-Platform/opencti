import { head, last, mapObjIndexed, pipe, values, join } from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import moment from 'moment';
import { DatabaseError } from '../config/errors';
import { isInternalObject } from '../schema/internalObject';
import { isStixMetaObject } from '../schema/stixMetaObject';
import { isStixDomainObject } from '../schema/stixDomainObject';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_DIRECTORY,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  isStixCyberObservable
} from "../schema/stixCyberObservableObject";
import { isInternalRelationship } from '../schema/internalRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';
import { isStixMetaRelationship } from '../schema/stixMetaRelationship';
import { isStixRelationship } from '../schema/stixRelationship';

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
      const nodeOffset = offset + parseInt(key, 10) + 1;
      return { node, cursor: offsetToCursor(nodeOffset) };
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
  if (isStixCoreRelationship(conceptType)) return INDEX_STIX_CORE_RELATIONSHIPS;
  if (isStixSightingRelationship(conceptType)) return INDEX_STIX_SIGHTING_RELATIONSHIPS;
  if (isStixCyberObservableRelationship(conceptType)) return INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS;
  if (isStixMetaRelationship(conceptType)) return INDEX_STIX_META_RELATIONSHIPS;
  throw DatabaseError(`Cant find index for type ${conceptType}`);
};

export const observableValue = (stixCyberObservable) => {
  switch (stixCyberObservable.entity_type) {
    case ENTITY_AUTONOMOUS_SYSTEM:
      return stixCyberObservable.number || 'Unknown';
    case ENTITY_DIRECTORY:
      return stixCyberObservable.path || 'Unknown';
    case ENTITY_EMAIL_MESSAGE:
      return stixCyberObservable.body || stixCyberObservable.subject;
    case ENTITY_HASHED_OBSERVABLE_ARTIFACT:
      if (values(stixCyberObservable.hashes).length > 0) {
        return values(stixCyberObservable.hashes)[0];
      }
      return stixCyberObservable.payload_bin || 'Unknown';
    case ENTITY_HASHED_OBSERVABLE_STIX_FILE:
      if (values(stixCyberObservable.hashes).length > 0) {
        return values(stixCyberObservable.hashes)[0];
      }
      return stixCyberObservable.name || 'Unknown';
    case ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE:
      if (values(stixCyberObservable.hashes).length > 0) {
        return values(stixCyberObservable.hashes)[0];
      }
      return stixCyberObservable.subject || stixCyberObservable.issuer || 'Unknown';
    case ENTITY_MUTEX:
      return stixCyberObservable.name || 'Unknown';
    case ENTITY_NETWORK_TRAFFIC:
      return stixCyberObservable.dst_port || 'Unknown';
    case ENTITY_PROCESS:
      return stixCyberObservable.pid || 'Unknown';
    case ENTITY_SOFTWARE:
      return stixCyberObservable.name || 'Unknown';
    case ENTITY_USER_ACCOUNT:
      return stixCyberObservable.account_login || 'Unknown';
    case ENTITY_WINDOWS_REGISTRY_KEY:
      return stixCyberObservable.attribute_key;
    default:
      return stixCyberObservable.value || 'Unknown';
  }
};

const extractEntityMainValue = (entityData) => {
  let mainValue;
  if (entityData.definition) {
    mainValue = entityData.definition;
  } else if (entityData.value) {
    mainValue = entityData.value;
  } else if (entityData.attribute_abstract) {
    mainValue = entityData.attribute_abstract;
  } else if (entityData.opinion) {
    mainValue = entityData.opinion;
  } else if (entityData.observable_value) {
    mainValue = entityData.observable_value;
  } else if (entityData.indicator_pattern) {
    mainValue = entityData.indicator_pattern;
  } else if (entityData.source_name) {
    mainValue = `${entityData.source_name}${entityData.external_id ? ` (${entityData.external_id})` : ''}`;
  } else if (entityData.phase_name) {
    mainValue = entityData.phase_name;
  } else if (entityData.first_observed && entityData.last_observed) {
    mainValue = `${moment(entityData.first_observed).utc().toISOString()} - ${moment(entityData.last_observed)
      .utc()
      .toISOString()}`;
  } else if (entityData.name) {
    mainValue = entityData.name;
  } else if (entityData.description) {
    mainValue = entityData.description;
  } else {
    mainValue = observableValue(entityData);
  }
  return mainValue;
};

export const generateLogMessage = (eventType, eventUser, eventData, eventExtraData) => {
  let fromValue;
  let fromType;
  let toValue;
  let toType;
  let toRelationshipType;
  if (eventExtraData && eventExtraData.from) {
    fromValue = extractEntityMainValue(eventExtraData.from);
    fromType = eventExtraData.from.entity_type;
  }
  if (eventExtraData && eventExtraData.to) {
    toValue = extractEntityMainValue(eventExtraData.to);
    toType = eventExtraData.to.entity_type;
    toRelationshipType = eventExtraData.to.entity_type;
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
  } else if (isStixMetaRelationship(eventData.entity_type)) {
    if (eventType === 'update') {
      message += `\`${eventData.entity_type}\` with the value \`${toValue}\`.`;
    } else if (isStixRelationship(toType)) {
      message += `relation \`${toRelationshipType}\`${toValue ? `with value \`${toValue}\`` : ''}.`;
    } else {
      message += `\`${toType}\` with value \`${toValue}\`.`;
    }
  } else if (eventExtraData.key && eventType === 'update') {
    message += `\`${eventExtraData.key}\` with \`${join(', ', eventExtraData.value)}\`.`;
  } else {
    message += `${eventData.entity_type} \`${name}\`.`;
  }
  return message;
};

export const pascalize = (s) => {
  return s.replace(/(\w)(\w*)/g, (g0, g1, g2) => {
    return g1.toUpperCase() + g2.toLowerCase();
  });
};
