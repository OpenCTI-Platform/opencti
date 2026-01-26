import * as R from 'ramda';
import moment, { type DurationInputArg2 } from 'moment/moment';
import type { SortResults } from '@elastic/elasticsearch/lib/api/types';
import { DatabaseError, UnsupportedError } from '../config/errors';
import { isHistoryObject, isInternalObject } from '../schema/internalObject';
import { isStixMetaObject } from '../schema/stixMetaObject';
import { isStixDomainObject, isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { isInternalRelationship, RELATION_IN_PIR } from '../schema/internalRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import conf from '../config/conf';
import { now } from '../utils/format';
import { isStixRefRelationship, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { getDraftContext } from '../utils/draftContext';
import { INPUT_OBJECTS } from '../schema/general';
import { doYield } from '../utils/eventloop-utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicNodeEdge, BasicStoreCommon, InternalEditInput, StoreCommon, BasicConnection } from '../types/store';
import type { AttributeDefinition, BasicObjectDefinition } from '../schema/attribute-definition';

export const ES_INDEX_PREFIX = conf.get('elasticsearch:index_prefix') || 'opencti';
const rabbitmqPrefix = conf.get('rabbitmq:queue_prefix');
export const RABBIT_QUEUE_PREFIX = rabbitmqPrefix ? `${rabbitmqPrefix}_` : '';

export const REDACTED_INFORMATION = '*** Redacted ***';
export const RESTRICTED_INFORMATION = 'Restricted';

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
export const INDEX_DELETED_OBJECTS = `${ES_INDEX_PREFIX}_deleted_objects`;
export const READ_INDEX_DELETED_OBJECTS = `${INDEX_DELETED_OBJECTS}*`;
export const INDEX_FILES = `${ES_INDEX_PREFIX}_files`;
export const READ_INDEX_FILES = `${INDEX_FILES}*`;
export const INDEX_HISTORY = `${ES_INDEX_PREFIX}_history`;
export const READ_INDEX_HISTORY = `${INDEX_HISTORY}*`;
export const INDEX_INTERNAL_OBJECTS = `${ES_INDEX_PREFIX}_internal_objects`;
export const READ_INDEX_INTERNAL_OBJECTS = `${INDEX_INTERNAL_OBJECTS}*`;
const INDEX_STIX_META_OBJECTS = `${ES_INDEX_PREFIX}_stix_meta_objects`;
export const READ_INDEX_STIX_META_OBJECTS = `${INDEX_STIX_META_OBJECTS}*`;
export const INDEX_STIX_DOMAIN_OBJECTS = `${ES_INDEX_PREFIX}_stix_domain_objects`;
export const READ_INDEX_STIX_DOMAIN_OBJECTS = `${INDEX_STIX_DOMAIN_OBJECTS}*`;
const INDEX_STIX_CYBER_OBSERVABLES = `${ES_INDEX_PREFIX}_stix_cyber_observables`;
export const READ_INDEX_STIX_CYBER_OBSERVABLES = `${INDEX_STIX_CYBER_OBSERVABLES}*`;

// Relations
const INDEX_INTERNAL_RELATIONSHIPS = `${ES_INDEX_PREFIX}_internal_relationships`;
export const READ_INDEX_INTERNAL_RELATIONSHIPS = `${INDEX_INTERNAL_RELATIONSHIPS}*`;
export const INDEX_STIX_CORE_RELATIONSHIPS = `${ES_INDEX_PREFIX}_stix_core_relationships`;
export const READ_INDEX_STIX_CORE_RELATIONSHIPS = `${INDEX_STIX_CORE_RELATIONSHIPS}*`;
const INDEX_STIX_SIGHTING_RELATIONSHIPS = `${ES_INDEX_PREFIX}_stix_sighting_relationships`;
export const READ_INDEX_STIX_SIGHTING_RELATIONSHIPS = `${INDEX_STIX_SIGHTING_RELATIONSHIPS}*`;
const INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS = `${ES_INDEX_PREFIX}_stix_cyber_observable_relationships`;
export const READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS = `${INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS}*`;
export const INDEX_STIX_META_RELATIONSHIPS = `${ES_INDEX_PREFIX}_stix_meta_relationships`;
export const READ_INDEX_STIX_META_RELATIONSHIPS = `${INDEX_STIX_META_RELATIONSHIPS}*`;

// Inferences
export const INDEX_INFERRED_ENTITIES = `${ES_INDEX_PREFIX}_inferred_entities`;
export const READ_INDEX_INFERRED_ENTITIES = `${INDEX_INFERRED_ENTITIES}*`;
export const INDEX_INFERRED_RELATIONSHIPS = `${ES_INDEX_PREFIX}_inferred_relationships`;
export const READ_INDEX_INFERRED_RELATIONSHIPS = `${INDEX_INFERRED_RELATIONSHIPS}*`;
export const INDEX_DRAFT_OBJECTS = `${ES_INDEX_PREFIX}_draft_objects`;
export const READ_INDEX_DRAFT_OBJECTS = `${INDEX_DRAFT_OBJECTS}*`;

export const isInferredIndex = (
  index: string | undefined | null,
): boolean => !!index && (index.startsWith(INDEX_INFERRED_ENTITIES) || index.startsWith(INDEX_INFERRED_RELATIONSHIPS));
export const isDraftIndex = (index: string | undefined | null): boolean => !!index && index.startsWith(INDEX_DRAFT_OBJECTS);

// indices that we only use as read only, not created anymore on new platforms
export const DEPRECATED_INDICES = [
  INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
];
export const WRITE_PLATFORM_INDICES = [
  INDEX_DELETED_OBJECTS,
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
  INDEX_DRAFT_OBJECTS,
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
  ...READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED,
];
export const READ_DATA_INDICES_INFERRED = [
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
];
export const READ_DATA_INDICES_WITHOUT_INTERNAL = [
  ...READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED,
  ...READ_DATA_INDICES_INFERRED,
];
export const READ_DATA_INDICES = [
  ...READ_DATA_INDICES_WITHOUT_INFERRED,
  ...READ_DATA_INDICES_INFERRED,
];

export const READ_STIX_DATA_WITH_INFERRED = [
  ...READ_STIX_INDICES,
  ...READ_DATA_INDICES_INFERRED,
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

export const isNotEmptyField = (field: any): boolean => !R.isEmpty(field) && !R.isNil(field);
export const isEmptyField = (field: any): boolean => !isNotEmptyField(field);

export const getIndicesToQuery = (context: AuthContext, user: AuthUser, index: string | string[] | undefined | null): string => {
  const draftContext = getDraftContext(context, user);
  return index + (!draftContext ? '' : (`,${READ_INDEX_DRAFT_OBJECTS}`));
};

const getMonday = (d: Date): Date => {
  const day = d.getDay();
  const diff = d.getDate() - day + (day === 0 ? -6 : 1); // adjust when day is sunday
  return new Date(d.setDate(diff));
};

export const fillTimeSeries = (startDate: Date, endDate: Date, interval: string, data: any[]) => {
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
    case 'hour':
      dateFormat = 'YYYY-MM-DD HH:mm:ss';
      break;
    default:
      dateFormat = 'YYYY-MM-DD';
  }
  const startFormatDate = new Date(endDateParsed.format(dateFormat));
  const endFormatDate = new Date(startDateParsed.format(dateFormat));
  const duration: DurationInputArg2 = `${interval}s` as DurationInputArg2;
  const elementsOfInterval = moment(startFormatDate).diff(moment(endFormatDate), duration);
  const newData = [];
  for (let i = 0; i <= elementsOfInterval; i += 1) {
    const workDate = moment(startDateParsed).add(i, duration);
    // Looking for the value
    let dataValue = 0;
    for (let j = 0; j < data.length; j += 1) {
      if (data[j].date === workDate.format(dateFormat)) {
        dataValue = data[j].value;
      }
    }
    const intervalDate = moment(workDate).startOf(interval as moment.unitOfTime.StartOf).utc().toISOString();
    newData[i] = {
      date: intervalDate,
      value: dataValue,
    };
  }
  return newData;
};

export const offsetToCursor = (sort: SortResults): string => {
  const objJsonStr = JSON.stringify(sort);
  return Buffer.from(objJsonStr, 'utf-8').toString('base64');
};

export const cursorToOffset = (cursor: string): SortResults => {
  const buff = Buffer.from(cursor, 'base64');
  const str = buff.toString('utf-8');
  return JSON.parse(str);
};

export const toBase64 = (utf8String: string | null | undefined): string | undefined => {
  if (isEmptyField(utf8String)) return undefined;
  const buff = Buffer.from(utf8String as string, 'utf-8');
  return buff.toString('base64');
};

export const fromBase64 = (base64String: string | null | undefined): string | undefined => {
  if (isEmptyField(base64String)) return undefined;
  const buff = Buffer.from(base64String as string, 'base64');
  return buff.toString('utf-8');
};

export const emptyPaginationResult = <T extends BasicStoreCommon>(): BasicConnection<T> => {
  return {
    edges: [],
    pageInfo: {
      startCursor: '',
      endCursor: '',
      hasNextPage: false,
      hasPreviousPage: false,
      globalCount: 0,
    },
  };
};

export const buildPaginationFromEdges = <T>(
  limit: number | undefined,
  searchAfter: string | undefined | null,
  edges: BasicNodeEdge<T>[],
  globalCount: number,
  filteredCount = 0,
): BasicConnection<T> => {
  // Because of stateless approach its difficult to know if its finish
  // this test could lead to an extra round trip sometimes
  const hasNextPage = (edges.length + filteredCount) === limit;
  // For same reason its difficult to know if a previous page exists.
  // Considering for now that if user specific an offset, it should exists a previous page.
  const hasPreviousPage = searchAfter !== undefined && searchAfter !== null;
  const startCursor = edges.length > 0 ? edges[0].cursor : '';
  const endCursor = edges.length > 0 ? edges[edges.length - 1].cursor : '';
  const pageInfo = {
    startCursor,
    endCursor,
    hasNextPage,
    hasPreviousPage,
    globalCount,
  };
  return { edges, pageInfo };
};

export const buildPagination = <T> (
  limit: number,
  searchAfter: string | undefined | null,
  instances: { node: T; sort?: SortResults; types?: string[] }[],
  globalCount: number,
  filteredCount = 0,
): BasicConnection<T> => {
  // TODO Make this transformation async
  const edges = instances.map((record) => {
    const { node, sort, types } = record;
    const cursor = sort ? offsetToCursor(sort) : '';
    return { node, cursor, types };
  });
  return buildPaginationFromEdges<T>(limit, searchAfter, edges, globalCount, filteredCount);
};

export const inferIndexFromConceptType = (conceptType: string, inferred = false): string => {
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

export const pascalize = (s: string): string => {
  return s.replace(/(\w)(\w*)/g, (g0, g1, g2) => {
    return g1.toUpperCase() + g2.toLowerCase();
  });
};

export const computeSumOfList = (numbers: number[]): number => {
  return numbers.reduce((a, b) => a + b, 0);
};

export const computeAverage = (numbers: number[]): number => {
  const sum = computeSumOfList(numbers);
  return Math.round(sum / numbers.length || 0);
};

export const wait = (ms: number): Promise<void> => {
  return new Promise((resolve) => setTimeout(() => resolve(), ms));
};

export const waitInSec = (sec: number): Promise<void> => wait(sec * 1000);

export const extractIdsFromStoreObject = (instance: BasicStoreCommon): string[] => {
  const ids = [instance.internal_id, ...(instance.x_opencti_stix_ids ?? [])];
  if (instance.standard_id) {
    ids.push(instance.standard_id);
  }
  return ids;
};

export const extractObjectsPirsFromInputs = (inputs: InternalEditInput[], entityType: string): { pir_ids: string[] } => {
  const pir_ids: string[] = [];
  if (isStixDomainObjectContainer(entityType)) {
    inputs.forEach((input) => {
      if (input && input.key === INPUT_OBJECTS && input.value?.length > 0) {
        const pirIds = input.value.flatMap((value) => (value as Record<string, any>)[RELATION_IN_PIR] ?? []);
        pir_ids.push(...pirIds);
      }
    });
  }
  return { pir_ids };
};

export const extractObjectsRestrictionsFromInputs = (inputs: InternalEditInput[], entityType: string): { markings: string [] } => {
  const markings: string[] = [];
  if (isStixDomainObjectContainer(entityType)) {
    inputs.forEach((input) => {
      if (input && input.key === INPUT_OBJECTS && input.value?.length > 0) {
        const objectMarking = input.value.flatMap((value) => (value as Record<string, any>)[RELATION_OBJECT_MARKING] ?? []);
        markings.push(...objectMarking);
      }
    });
  }
  return {
    markings,
  };
};

export const isObjectPathTargetMultipleAttribute = (instance: BasicStoreCommon, object_path: string): boolean => {
  const preparedPath = object_path.startsWith('/') ? object_path : `/${object_path}`;
  const pathArray = preparedPath.split('/').filter((p) => isNotEmptyField(p));
  let currentAttr: AttributeDefinition | undefined;
  for (let i = 0; i < pathArray.length; i += 1) {
    const arrElement = pathArray[i];
    if (!currentAttr) {
      currentAttr = schemaAttributesDefinition.getAttribute(instance.entity_type, arrElement);
    } else {
      let mappings: BasicObjectDefinition['mappings'] = [];
      if ('mappings' in currentAttr) {
        mappings = currentAttr.mappings;
      }
      const newAttributeMapping = mappings.find((m) => m.name === arrElement);
      currentAttr = newAttributeMapping || currentAttr;
    }
  }
  if (currentAttr) {
    // If the last element of the path is a number, this is cancelling the multiple effect
    const noMultipleRestriction = Number.isNaN(Number(pathArray[pathArray.length - 1]));
    return currentAttr.multiple && noMultipleRestriction;
  }
  throw UnsupportedError('Invalid schema pointer for partial update', { path: object_path });
};

export const asyncListTransformation = async <T> (
  elements: StoreCommon[],
  preparatoryFunction: (instance: StoreCommon) => T): Promise<T[]> => {
  const preparedElements = [];
  for (let n = 0; n < elements.length; n += 1) {
    await doYield();
    const element = elements[n];
    const preparedElement = preparatoryFunction(element);
    preparedElements.push(preparedElement);
  }
  return preparedElements;
};
