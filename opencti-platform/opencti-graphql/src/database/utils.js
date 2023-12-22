import * as R from 'ramda';
import moment from 'moment';
import { DatabaseError, UnsupportedError } from '../config/errors';
import { isHistoryObject, isInternalObject } from '../schema/internalObject';
import { isStixMetaObject } from '../schema/stixMetaObject';
import { isStixDomainObject } from '../schema/stixDomainObject';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { isInternalRelationship } from '../schema/internalRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import conf from '../config/conf';
import { now } from '../utils/format';
import { isStixRefRelationship } from '../schema/stixRefRelationship';
import { schemaAttributesDefinition } from '../schema/schema-attributes';

export const ES_INDEX_PREFIX = conf.get('elasticsearch:index_prefix') || 'opencti';
const rabbitmqPrefix = conf.get('rabbitmq:queue_prefix');
export const RABBIT_QUEUE_PREFIX = rabbitmqPrefix ? `${rabbitmqPrefix}_` : '';

export const INTERNAL_SYNC_QUEUE = 'sync';
export const INTERNAL_PLAYBOOK_QUEUE = 'playbook';
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
export const INDEX_FILES = `${ES_INDEX_PREFIX}_files`;
export const READ_INDEX_FILES = `${INDEX_FILES}*`;
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
  INDEX_FILES,
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
  INDEX_STIX_META_RELATIONSHIPS,
];

export const READ_STIX_INDICES = [
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
];
export const READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED = [
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_META_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  ...READ_STIX_INDICES,
];
export const READ_DATA_INDICES_WITHOUT_INFERRED = [
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_INTERNAL_RELATIONSHIPS,
  ...READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED
];
export const READ_DATA_INDICES_INFERRED = [
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
];
export const READ_DATA_INDICES_WITHOUT_INTERNAL = [
  ...READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED,
  ...READ_DATA_INDICES_INFERRED
];
export const READ_DATA_INDICES = [
  ...READ_DATA_INDICES_WITHOUT_INFERRED,
  ...READ_DATA_INDICES_INFERRED
];
export const READ_PLATFORM_INDICES = [READ_INDEX_HISTORY, ...READ_DATA_INDICES];
export const READ_ENTITIES_INDICES_WITHOUT_INFERRED = [
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
];
export const READ_ENTITIES_INDICES = [
  ...READ_ENTITIES_INDICES_WITHOUT_INFERRED,
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
    /* v8 ignore next */
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

export const toBase64 = (utf8String) => {
  if (isEmptyField(utf8String)) return undefined;
  const buff = Buffer.from(utf8String, 'utf-8');
  return buff.toString('base64');
};

export const fromBase64 = (base64String) => {
  if (isEmptyField(base64String)) return undefined;
  const buff = Buffer.from(base64String, 'base64');
  return buff.toString('utf-8');
};

export const buildPagination = (limit, searchAfter, instances, globalCount) => {
  const edges = R.pipe(
    R.mapObjIndexed((record) => {
      const { node, sort, types } = record;
      const cursor = sort ? offsetToCursor(sort) : '';
      return { node, cursor, types };
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
    if (isStixRefRelationship(conceptType)) return INDEX_INFERRED_RELATIONSHIPS;
    if (isInternalRelationship(conceptType)) return INDEX_INFERRED_RELATIONSHIPS;
    throw DatabaseError('Cant find inferred index', { type: conceptType });
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

  // Use only META Index on new ref relationship
  if (isStixRefRelationship(conceptType)) return INDEX_STIX_META_RELATIONSHIPS;

  throw DatabaseError('Cant find index', { type: conceptType });
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

export const extractIdsFromStoreObject = (instance) => {
  const ids = [instance.internal_id, ...(instance.x_opencti_stix_ids ?? [])];
  if (instance.standard_id) {
    ids.push(instance.standard_id);
  }
  return ids;
};

export const isPointersTargetMultipleAttribute = (instance, pointers) => {
  const pathArray = pointers[0].split('/').filter((p) => isNotEmptyField(p));
  let currentAttr;
  for (let i = 0; i < pathArray.length; i += 1) {
    const arrElement = pathArray[i];
    if (!currentAttr) {
      currentAttr = schemaAttributesDefinition.getAttribute(instance.entity_type, arrElement);
    } else {
      const mappings = currentAttr.mappings ?? [];
      const newAttributeMapping = mappings.find((m) => m.name === arrElement);
      currentAttr = newAttributeMapping || currentAttr;
    }
  }
  if (currentAttr) {
    // If the last element of the path is a number, this is cancelling the multiple effect
    const noMultipleRestriction = Number.isNaN(Number(R.last(pathArray)));
    return currentAttr.multiple && noMultipleRestriction;
  }
  throw UnsupportedError('Invalid schema pointer for partial uppdate', { pointer: pointers[0] });
};
