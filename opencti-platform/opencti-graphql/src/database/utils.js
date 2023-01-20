import * as R from 'ramda';
import moment from 'moment';
import { DatabaseError, UnsupportedError } from '../config/errors';
import { isHistoryObject, isInternalObject } from '../schema/internalObject';
import { isStixMetaObject } from '../schema/stixMetaObject';
import { isStixDomainObject } from '../schema/stixDomainObject';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE, isStixCyberObservable } from '../schema/stixCyberObservable';
import { isInternalRelationship } from '../schema/internalRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import {
  isStixCyberObservableRelationship,
  STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE
} from '../schema/stixCyberObservableRelationship';
import { isStixMetaRelationship, metaFieldToStixAttribute } from '../schema/stixMetaRelationship';
import { isStixObject } from '../schema/stixCoreObject';
import conf from '../config/conf';
import { now, observableValue } from '../utils/format';
import { isStixRelationship } from '../schema/stixRelationship';
import { isDictionaryAttribute, isJsonAttribute } from '../schema/fieldDataAdapter';
import { truncate } from '../utils/mailData';

export const ES_INDEX_PREFIX = conf.get('elasticsearch:index_prefix') || 'opencti';
const rabbitmqPrefix = conf.get('rabbitmq:queue_prefix');
export const RABBIT_QUEUE_PREFIX = rabbitmqPrefix ? `${rabbitmqPrefix}_` : '';

export const INTERNAL_SYNC_QUEUE = 'sync';
export const EVENT_TYPE_CREATE = 'create';
export const EVENT_TYPE_DELETE = 'delete';
export const EVENT_TYPE_DEPENDENCIES = 'init-dependencies';
export const EVENT_TYPE_INIT = 'init-create';
export const EVENT_TYPE_UPDATE = 'update';
export const EVENT_TYPE_MERGE = 'merge';

// Operations definition
export const UPDATE_OPERATION_ADD = 'add';
export const UPDATE_OPERATION_REPLACE = 'replace';
export const UPDATE_OPERATION_REMOVE = 'remove';

// Entities
export const INDEX_HISTORY = `${ES_INDEX_PREFIX}_history`;
export const READ_INDEX_HISTORY = `${INDEX_HISTORY}*`;
export const INDEX_INTERNAL_OBJECTS = `${ES_INDEX_PREFIX}_internal_objects`;
export const READ_INDEX_INTERNAL_OBJECTS = `${INDEX_INTERNAL_OBJECTS}*`;
const INDEX_STIX_META_OBJECTS = `${ES_INDEX_PREFIX}_stix_meta_objects`;
export const READ_INDEX_STIX_META_OBJECTS = `${INDEX_STIX_META_OBJECTS}*`;
const INDEX_STIX_DOMAIN_OBJECTS = `${ES_INDEX_PREFIX}_stix_domain_objects`;
export const READ_INDEX_STIX_DOMAIN_OBJECTS = `${INDEX_STIX_DOMAIN_OBJECTS}*`;
const INDEX_STIX_CYBER_OBSERVABLES = `${ES_INDEX_PREFIX}_stix_cyber_observables`;
export const READ_INDEX_STIX_CYBER_OBSERVABLES = `${INDEX_STIX_CYBER_OBSERVABLES}*`;

// Relations
const INDEX_INTERNAL_RELATIONSHIPS = `${ES_INDEX_PREFIX}_internal_relationships`;
export const READ_INDEX_INTERNAL_RELATIONSHIPS = `${INDEX_INTERNAL_RELATIONSHIPS}*`;
const INDEX_STIX_CORE_RELATIONSHIPS = `${ES_INDEX_PREFIX}_stix_core_relationships`;
export const READ_INDEX_STIX_CORE_RELATIONSHIPS = `${INDEX_STIX_CORE_RELATIONSHIPS}*`;
const INDEX_STIX_SIGHTING_RELATIONSHIPS = `${ES_INDEX_PREFIX}_stix_sighting_relationships`;
export const READ_INDEX_STIX_SIGHTING_RELATIONSHIPS = `${INDEX_STIX_SIGHTING_RELATIONSHIPS}*`;
const INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS = `${ES_INDEX_PREFIX}_stix_cyber_observable_relationships`;
export const READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS = `${INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS}*`;
const INDEX_STIX_META_RELATIONSHIPS = `${ES_INDEX_PREFIX}_stix_meta_relationships`;
export const READ_INDEX_STIX_META_RELATIONSHIPS = `${INDEX_STIX_META_RELATIONSHIPS}*`;

// Inferences
export const INDEX_INFERRED_ENTITIES = `${ES_INDEX_PREFIX}_inferred_entities`;
export const READ_INDEX_INFERRED_ENTITIES = `${INDEX_INFERRED_ENTITIES}*`;
export const INDEX_INFERRED_RELATIONSHIPS = `${ES_INDEX_PREFIX}_inferred_relationships`;
export const READ_INDEX_INFERRED_RELATIONSHIPS = `${INDEX_INFERRED_RELATIONSHIPS}*`;
export const isInferredIndex = (index) => index.startsWith(INDEX_INFERRED_ENTITIES) || index.startsWith(INDEX_INFERRED_RELATIONSHIPS);

export const WRITE_PLATFORM_INDICES = [
  INDEX_HISTORY,
  INDEX_INTERNAL_OBJECTS,
  INDEX_STIX_META_OBJECTS,
  INDEX_STIX_DOMAIN_OBJECTS,
  INDEX_STIX_CYBER_OBSERVABLES,
  INDEX_INTERNAL_RELATIONSHIPS,
  INDEX_STIX_CORE_RELATIONSHIPS,
  INDEX_INFERRED_ENTITIES,
  INDEX_INFERRED_RELATIONSHIPS,
  INDEX_STIX_SIGHTING_RELATIONSHIPS,
  INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  INDEX_STIX_META_RELATIONSHIPS,
];

export const READ_STIX_INDICES = [
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
];
export const READ_DATA_INDICES_WITHOUT_INFERRED = [
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_INTERNAL_RELATIONSHIPS,
  READ_INDEX_STIX_META_RELATIONSHIPS,
  ...READ_STIX_INDICES,
];
export const READ_DATA_INDICES_INFERRED = [
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
];
export const READ_DATA_INDICES = [
  ...READ_DATA_INDICES_WITHOUT_INFERRED,
  ...READ_DATA_INDICES_INFERRED
];
export const READ_PLATFORM_INDICES = [READ_INDEX_HISTORY, ...READ_DATA_INDICES];
export const READ_ENTITIES_INDICES = [
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_INFERRED_ENTITIES,
];
export const READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED = [
  READ_INDEX_INTERNAL_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  READ_INDEX_STIX_META_RELATIONSHIPS,
];
export const READ_RELATIONSHIPS_INDICES = [
  ...READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
  READ_INDEX_INFERRED_RELATIONSHIPS,
];

export const isNotEmptyField = (field) => !R.isEmpty(field) && !R.isNil(field);
export const isEmptyField = (field) => !isNotEmptyField(field);

const getMonday = (d) => {
  const day = d.getDay();
  const diff = d.getDate() - day + (day === 0 ? -6 : 1); // adjust when day is sunday
  return new Date(d.setDate(diff));
};

export const fillTimeSeries = (startDate, endDate, interval, data) => {
  let startDateParsed = moment.parseZone(startDate);
  let endDateParsed = moment.parseZone(endDate ?? now());
  let dateFormat;
  switch (interval) {
    case 'year':
      dateFormat = 'YYYY';
      break;
    case 'quarter':
    case 'month':
      dateFormat = 'YYYY-MM';
      break;
    /* istanbul ignore next */
    case 'week':
      dateFormat = 'YYYY-MM-DD';
      startDateParsed = moment.parseZone(getMonday(new Date(startDateParsed.format(dateFormat))).toISOString());
      endDateParsed = moment.parseZone(getMonday(new Date(endDateParsed.format(dateFormat))).toISOString());
      break;
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

export const offsetToCursor = (sort) => {
  const objJsonStr = JSON.stringify(sort);
  return Buffer.from(objJsonStr, 'utf-8').toString('base64');
};

export const cursorToOffset = (cursor) => {
  const buff = Buffer.from(cursor, 'base64');
  const str = buff.toString('utf-8');
  return JSON.parse(str);
};

export const buildPagination = (limit, searchAfter, instances, globalCount) => {
  const edges = R.pipe(
    R.mapObjIndexed((record) => {
      const { node, sort } = record;
      const cursor = sort ? offsetToCursor(sort) : '';
      return { node, cursor };
    }),
    R.values
  )(instances);
  // Because of stateless approach its difficult to know if its finish
  // this test could lead to an extra round trip sometimes
  const hasNextPage = instances.length === limit;
  // For same reason its difficult to know if a previous page exists.
  // Considering for now that if user specific an offset, it should exists a previous page.
  const hasPreviousPage = searchAfter !== undefined && searchAfter !== null;
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

export const inferIndexFromConceptType = (conceptType, inferred = false) => {
  // Inferred support
  if (inferred) {
    if (isStixDomainObject(conceptType)) return INDEX_INFERRED_ENTITIES;
    if (isStixCoreRelationship(conceptType)) return INDEX_INFERRED_RELATIONSHIPS;
    if (isStixSightingRelationship(conceptType)) return INDEX_INFERRED_RELATIONSHIPS;
    if (isStixMetaRelationship(conceptType)) return INDEX_INFERRED_RELATIONSHIPS;
    if (isInternalRelationship(conceptType)) return INDEX_INFERRED_RELATIONSHIPS;
    throw DatabaseError(`Cant find inferred index for type ${conceptType}`);
  }
  // Entities
  if (isHistoryObject(conceptType)) return INDEX_HISTORY;
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

// TODO migrate to extractStixRepresentative from convertStoreToStix
export const extractEntityRepresentative = (entityData) => {
  let mainValue;
  if (isStixCyberObservable(entityData.entity_type)) {
    mainValue = observableValue(entityData);
  } else if (isNotEmptyField(entityData.definition)) {
    mainValue = entityData.definition;
  } else if (isNotEmptyField(entityData.value)) {
    mainValue = entityData.value;
  } else if (isNotEmptyField(entityData.attribute_abstract)) {
    mainValue = entityData.attribute_abstract;
  } else if (isNotEmptyField(entityData.opinion)) {
    mainValue = entityData.opinion;
  } else if (isNotEmptyField(entityData.observable_value)) {
    mainValue = entityData.observable_value;
  } else if (isNotEmptyField(entityData.indicator_pattern)) {
    mainValue = entityData.indicator_pattern;
  } else if (isNotEmptyField(entityData.source_name)) {
    mainValue = `${entityData.source_name}${entityData.external_id ? ` (${entityData.external_id})` : ''}`;
  } else if (isNotEmptyField(entityData.kill_chain_name)) {
    mainValue = entityData.kill_chain_name;
  } else if (isNotEmptyField(entityData.phase_name)) {
    mainValue = entityData.phase_name;
  } else if (isNotEmptyField(entityData.first_observed) && isNotEmptyField(entityData.last_observed)) {
    const from = moment(entityData.first_observed).utc().toISOString();
    const to = moment(entityData.last_observed).utc().toISOString();
    mainValue = `${from} - ${to}`;
  } else if (isNotEmptyField(entityData.name)) {
    mainValue = entityData.name;
  } else if (isNotEmptyField(entityData.description)) {
    mainValue = entityData.description;
  }
  // If no representative value found, return the standard id
  if (isEmptyField(mainValue) || mainValue === 'Unknown') {
    return entityData.standard_id;
  }
  return mainValue;
};

export const generateMergeMessage = (instance, sources) => {
  const name = extractEntityRepresentative(instance);
  const sourcesNames = sources.map((source) => extractEntityRepresentative(source)).join(', ');
  return `merges ${instance.entity_type} \`${sourcesNames}\` in \`${name}\``;
};
const generateCreateDeleteMessage = (type, instance) => {
  const name = extractEntityRepresentative(instance);
  if (isStixObject(instance.entity_type)) {
    let entityType = instance.entity_type;
    if (entityType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
      entityType = 'File';
    }
    return `${type}s a ${entityType} \`${name}\``;
  }
  if (isStixRelationship(instance.entity_type)) {
    const from = extractEntityRepresentative(instance.from);
    let fromType = instance.from.entity_type;
    if (fromType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
      fromType = 'File';
    }
    const to = extractEntityRepresentative(instance.to);
    let toType = instance.to.entity_type;
    if (toType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
      toType = 'File';
    }
    return `${type}s the relation ${instance.entity_type} from \`${from}\` (${fromType}) to \`${to}\` (${toType})`;
  }
  return '-';
};

export const generateCreateMessage = (instance) => {
  return generateCreateDeleteMessage(EVENT_TYPE_CREATE, instance);
};
export const generateDeleteMessage = (instance) => {
  return generateCreateDeleteMessage(EVENT_TYPE_DELETE, instance);
};

export const generateUpdateMessage = (inputs) => {
  const inputsByOperations = R.groupBy((m) => m.operation ?? UPDATE_OPERATION_REPLACE, inputs);
  const patchElements = Object.entries(inputsByOperations);
  if (patchElements.length === 0) {
    throw UnsupportedError('[OPENCTI] Error generating update message with empty inputs');
  }
  // noinspection UnnecessaryLocalVariableJS
  const generatedMessage = patchElements.slice(0, 3).map(([type, operations]) => {
    return `${type}s ${operations.slice(0, 3).map(({ key, value }) => {
      let message = 'nothing';
      let convertedKey = key;
      if (metaFieldToStixAttribute()[key]) {
        convertedKey = metaFieldToStixAttribute()[key];
      }
      if (STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE[key]) {
        convertedKey = STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE[key];
      }
      const fromArray = Array.isArray(value) ? value : [value];
      const values = fromArray.slice(0, 3).filter((v) => isNotEmptyField(v));
      if (isNotEmptyField(values)) {
        // If update is based on internal ref, we need to extract the value
        if (metaFieldToStixAttribute()[key] || STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE[key]) {
          message = values.map((val) => truncate(extractEntityRepresentative(val))).join(', ');
        } else if (isDictionaryAttribute(key)) {
          message = Object.entries(R.head(values)).map(([k, v]) => truncate(`${k}:${v}`)).join(', ');
        } else if (isJsonAttribute(key)) {
          message = values.map((v) => truncate(JSON.stringify(v)));
        } else {
          // If standard primitive data, just join the values
          message = values.join(', ');
        }
      }
      return `\`${message}\` in \`${convertedKey}\`${(fromArray.length > 3) ? ` and ${fromArray.length - 3} more items` : ''}`;
    }).join(' - ')}`;
  }).join(' | ');
  // Return generated update message
  return `${generatedMessage}${patchElements.length > 3 ? ` and ${patchElements.length - 3} more operations` : ''}`;
};

export const pascalize = (s) => {
  return s.replace(/(\w)(\w*)/g, (g0, g1, g2) => {
    return g1.toUpperCase() + g2.toLowerCase();
  });
};

export const computeAverage = (numbers) => {
  const sum = numbers.reduce((a, b) => a + b, 0);
  return Math.round(sum / numbers.length || 0);
};

export const wait = (ms) => {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
};

export const waitInSec = (sec) => wait(sec * 1000);
