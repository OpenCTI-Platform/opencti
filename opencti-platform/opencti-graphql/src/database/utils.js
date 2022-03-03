import * as R from 'ramda';
import moment from 'moment';
import { DatabaseError } from '../config/errors';
import { isHistoryObject, isInternalObject } from '../schema/internalObject';
import { isStixMetaObject } from '../schema/stixMetaObject';
import { isStixDomainObject } from '../schema/stixDomainObject';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE, isStixCyberObservable } from '../schema/stixCyberObservable';
import { isInternalRelationship } from '../schema/internalRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';
import { isStixMetaRelationship } from '../schema/stixMetaRelationship';
import { isStixObject } from '../schema/stixCoreObject';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE } from './rabbitmq';
import conf from '../config/conf';
import { now, observableValue } from '../utils/format';

export const ES_INDEX_PREFIX = conf.get('elasticsearch:index_prefix') || 'opencti';

// Operations definition
export const UPDATE_OPERATION_ADD = 'add';
export const UPDATE_OPERATION_REPLACE = 'replace';
export const UPDATE_OPERATION_REMOVE = 'remove';
export const UPDATE_OPERATION_CHANGE = 'change';

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
export const READ_DATA_INDICES = [
  ...READ_DATA_INDICES_WITHOUT_INFERRED,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
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

export const fillTimeSeries = (startDate, endDate, interval, data) => {
  const startDateParsed = moment.parseZone(startDate);
  const endDateParsed = moment.parseZone(endDate ?? now());
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

export const generateMergeMessage = (instance, sources) => {
  const name = extractEntityMainValue(instance);
  const sourcesNames = sources.map((source) => extractEntityMainValue(source)).join(', ');
  return `merges ${instance.entity_type} \`${sourcesNames}\` in \`${name}\``;
};
const generateCreateDeleteMessage = (type, instance) => {
  const name = extractEntityMainValue(instance);
  if (isStixObject(instance.entity_type)) {
    let entityType = instance.entity_type;
    if (entityType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
      entityType = 'File';
    }
    return `${type}s a ${entityType} \`${name}\``;
  }
  // Relation
  const from = extractEntityMainValue(instance.from);
  let fromType = instance.from.entity_type;
  if (fromType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
    fromType = 'File';
  }
  const to = extractEntityMainValue(instance.to);
  let toType = instance.to.entity_type;
  if (toType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
    toType = 'File';
  }
  return `${type}s the relation ${instance.entity_type} from \`${from}\` (${fromType}) to \`${to}\` (${toType})`;
};
export const generateCreateMessage = (instance) => {
  return generateCreateDeleteMessage(EVENT_TYPE_CREATE, instance);
};
export const generateDeleteMessage = (instance) => {
  return generateCreateDeleteMessage(EVENT_TYPE_DELETE, instance);
};
export const generateUpdateMessage = (patch) => {
  const patchElements = Object.entries(patch);
  return patchElements
    .map(([operation, element]) => {
      const elemEntries = Object.entries(element);
      return `${operation}s ${elemEntries.map(([key, val]) => {
        const values = Array.isArray(val) ? val : [val];
        const valMessage = values
          .map((v) => {
            if (operation === UPDATE_OPERATION_REPLACE) {
              if (Array.isArray(v.current)) {
                return v.current.map((c) => c.reference || c.value || c);
              }
              return v.reference?.value || v.current?.value || v.current;
            }
            return v.reference || v.value || v;
          })
          .join(', ');
        return `\`${valMessage || 'nothing'}\` in \`${key}\``;
      })}`;
    })
    .join(', ');
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
