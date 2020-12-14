import * as R from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import moment from 'moment';
import { DatabaseError, FunctionalError } from '../config/errors';
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
  isStixCyberObservable,
} from '../schema/stixCyberObservable';
import { isInternalRelationship } from '../schema/internalRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';
import {
  isStixInternalMetaRelationship,
  isStixMetaRelationship,
  RELATION_OBJECT_LABEL,
} from '../schema/stixMetaRelationship';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE } from './rabbitmq';
import { isStixObject } from '../schema/stixCoreObject';

export const UPDATE_OPERATION_ADD = 'add';
export const UPDATE_OPERATION_REPLACE = 'replace';
export const UPDATE_OPERATION_REMOVE = 'remove';
export const UPDATE_OPERATION_CHANGE = 'change';
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

export const isNotEmptyField = (field) => !R.isEmpty(field) && !R.isNil(field);
export const isEmptyField = (field) => !isNotEmptyField(field);

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
  const edges = R.pipe(
    R.mapObjIndexed((record, key) => {
      const { node } = record;
      const nodeOffset = offset + parseInt(key, 10) + 1;
      return { node, cursor: offsetToCursor(nodeOffset) };
    }),
    R.values
  )(instances);
  const hasNextPage = first + offset < globalCount;
  const hasPreviousPage = offset > 0;
  const startCursor = edges.length > 0 ? R.head(edges).cursor : '';
  const endCursor = edges.length > 0 ? R.last(edges).cursor : '';
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
      if (R.values(stixCyberObservable.hashes).length > 0) {
        return R.values(stixCyberObservable.hashes)[0];
      }
      return stixCyberObservable.payload_bin || 'Unknown';
    case ENTITY_HASHED_OBSERVABLE_STIX_FILE:
      if (R.values(stixCyberObservable.hashes).length > 0) {
        return R.values(stixCyberObservable.hashes)[0];
      }
      return stixCyberObservable.name || 'Unknown';
    case ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE:
      if (R.values(stixCyberObservable.hashes).length > 0) {
        return R.values(stixCyberObservable.hashes)[0];
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

export const relationTypeToInputName = (type) => {
  let inputName = '';
  const isMeta = isStixInternalMetaRelationship(type) && type !== RELATION_OBJECT_LABEL;
  const elements = type.split('-');
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    if (index > 0) {
      inputName += element.charAt(0).toUpperCase() + element.slice(1);
    } else {
      inputName += element;
    }
  }
  return inputName + (isMeta ? 's' : '');
};

const valToMessage = (val) => {
  if (Array.isArray(val)) {
    const values = R.filter((v) => isNotEmptyField(v), val);
    return values.length > 0 ? values.map((item) => valToMessage(item)) : null;
  }
  if (val && typeof val === 'object') {
    const valEntries = R.filter(([, v]) => isNotEmptyField(v), Object.entries(val));
    return valEntries.map(([k, v]) => `${k}: ${v}`).join(', ');
  }
  return isNotEmptyField(val) ? val.toString() : null;
};

export const generateLogMessage = (type, instance, input = null) => {
  const name = extractEntityMainValue(instance);
  if (type === EVENT_TYPE_CREATE || type === EVENT_TYPE_DELETE || type === EVENT_TYPE_MERGE) {
    if (isStixObject(instance.entity_type)) {
      return `${type}s a ${instance.entity_type} \`${name}\``;
    }
    // Relation
    const from = extractEntityMainValue(instance.from);
    const fromType = instance.from.entity_type;
    const to = extractEntityMainValue(instance.to);
    const toType = instance.to.entity_type;
    return `${type}s the relation ${instance.entity_type} from \`${from}\` (${fromType}) to \`${to}\` (${toType})`;
  }
  if (
    type === UPDATE_OPERATION_REPLACE ||
    type === UPDATE_OPERATION_ADD ||
    type === UPDATE_OPERATION_REMOVE ||
    type === UPDATE_OPERATION_CHANGE
  ) {
    const joiner = type === UPDATE_OPERATION_REPLACE ? 'by' : 'value';
    const fieldMessage = R.map(([key, val]) => {
      return `\`${key}\` ${joiner} \`${valToMessage(val) || 'nothing'}\``;
    }, Object.entries(input)).join(', ');
    return `${type}s the ${fieldMessage}`;
  }
  throw FunctionalError(`Cant generated message for event type ${type}`);
};

export const pascalize = (s) => {
  return s.replace(/(\w)(\w*)/g, (g0, g1, g2) => {
    return g1.toUpperCase() + g2.toLowerCase();
  });
};
