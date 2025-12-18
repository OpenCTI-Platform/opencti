import { extractEntityRepresentativeName } from './entity-representative';
import { isStixObject } from '../schema/stixCoreObject';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../schema/stixCyberObservable';
import { isBasicRelationship } from '../schema/stixRelationship';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, isEmptyField, isNotEmptyField, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from './utils';
import { isStoreRelationPir } from '../schema/internalRelationship';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import type { Change, ChangeValue } from '../types/event';
import { type AttributeDefinition, files } from '../schema/attribute-definition';
import { DefaultFormating, type Formating, humanizeDate } from '../utils/humanize';
import { internalFindByIdsMapped } from './middleware-loader';
import type { AuthContext, AuthUser } from '../types/user';
import { UnsupportedError } from '../config/errors';
import { getEntitiesMapFromCache } from './cache';
import { doYield } from '../utils/eventloop-utils';
import { utcDate } from '../utils/format';
import { INPUT_MARKINGS } from '../schema/general';

export const EMPTY_VALUE = 'nothing';
export const RESTRICTED_VALUE = 'Restricted';
export const UNTRANSLATED_VALUE = 'Untranslated';
const MAX_TRANSLATE_LENGTH = 50;
const MAX_OPERATIONS_FOR_MESSAGE = 3;

const buildMapFromCacheContext = (context: AuthContext, user: AuthUser) => {
  return async (type: string) => {
    return getEntitiesMapFromCache<any>(context, user, type);
  };
};

export const generateMergeMessage = (instance: any, sources: any[]) => {
  const name = extractEntityRepresentativeName(instance);
  const sourcesNames = sources.map((source) => extractEntityRepresentativeName(source)).join(', ');
  return `merges ${instance.entity_type} \`${sourcesNames}\` in \`${name}\``;
};

const generateCreateDeleteMessage = (type: string, instance: any) => {
  const name = extractEntityRepresentativeName(instance);
  if (isStoreRelationPir(instance)) {
    const action = type === EVENT_TYPE_CREATE ? 'added to' : 'removed from';
    const from = extractEntityRepresentativeName(instance.from);
    const fromType = instance.from?.entity_type;
    const to = extractEntityRepresentativeName(instance.to);
    const toType = instance.to?.entity_type;
    return `${fromType} \`${from}\` ${action} ${toType} \`${to}\``;
  }
  if (isStixObject(instance.entity_type)) {
    let entityType = instance.entity_type;
    if (entityType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
      entityType = 'File';
    }
    return `${type}s a ${entityType} \`${name}\``;
  }
  if (isBasicRelationship(instance.entity_type)) {
    const from = extractEntityRepresentativeName(instance.from);
    let fromType = instance.from.entity_type;
    if (fromType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
      fromType = 'File';
    }
    const to = extractEntityRepresentativeName(instance.to);
    let toType = instance.to.entity_type;
    if (toType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
      toType = 'File';
    }
    return `${type}s the relation ${instance.entity_type} from \`${from}\` (${fromType}) to \`${to}\` (${toType})`;
  }
  return '-';
};

export const generateCreateMessage = (instance: any) => {
  return generateCreateDeleteMessage(EVENT_TYPE_CREATE, instance);
};

export const generateDeleteMessage = (instance: any) => {
  return generateCreateDeleteMessage(EVENT_TYPE_DELETE, instance);
};

export const generateRestoreMessage = (instance: any) => {
  // this method is used only to generate a history message, there is no event restore in stream.
  return generateCreateDeleteMessage('restore', instance);
};

const resolveAttribute = (field: string) => {
  const fieldSplit = field.split('--');
  const key = fieldSplit[1];
  const entityType = fieldSplit[0];
  const attributeDefinition = schemaAttributesDefinition.getAttribute(entityType, key);
  const relationsRefDefinition = schemaRelationsRefDefinition.getRelationRef(entityType, key);
  return attributeDefinition || relationsRefDefinition;
};

export const humanizeRawValue = (resolvedMap: Record<string, string>,
  attribute: AttributeDefinition, v: ChangeValue, format: Formating = DefaultFormating): string => {
  const targetValue = v.raw;
  if (attribute.type === 'date') {
    return humanizeDate(targetValue, format);
  }
  if (attribute.type === 'string') {
    if (attribute.format === 'id' || attribute.format === 'json') {
      return attribute.representative?.(v.raw, resolvedMap, format) ?? UNTRANSLATED_VALUE;
    }
    return v.raw; // vocab / enum
  }
  if (attribute.type === 'boolean') {
    return v.raw.toLowerCase() === 'true' ? 'Yes' : 'No';
  }
  if (attribute.type === 'numeric') {
    return v.raw;
  }
  if (attribute.type === 'object') {
    try {
      const objectData = JSON.parse(v.raw);
      return attribute.representative?.(objectData, resolvedMap, format) ?? UNTRANSLATED_VALUE;
    } catch {
      return RESTRICTED_VALUE;
    }
  }
  if (attribute.type === 'ref') {
    return resolvedMap[v.raw] ?? RESTRICTED_VALUE;
  }
  return UNTRANSLATED_VALUE;
};

const humanizeChangeValues = (resolvedMap: Record<string, string>,
  field: string, changeValues: ChangeValue[] | undefined, format: Formating = DefaultFormating): string[] => {
  const attribute = resolveAttribute(field);
  if (!attribute) throw UnsupportedError('Cant resolve attribute', { field });
  const humanChangedValues: string[] = [];
  const values = changeValues ?? [];
  for (let index = 0; index < values.length; index += 1) {
    const v = values[index];
    const human = humanizeRawValue(resolvedMap, attribute, v, format);
    humanChangedValues.push(human);
  }
  return humanChangedValues;
};

const humanizeHistoryChange = (resolvedMap: Record<string, string>,
  attribute: AttributeDefinition | null, change: Change, format: Formating = DefaultFormating) => {
  return {
    field: attribute?.label ?? change.field,
    changes_added: humanizeChangeValues(resolvedMap, change.field, change.changes_added, format),
    changes_removed: humanizeChangeValues(resolvedMap, change.field, change.changes_removed, format),
  };
};

const humanizeHistoryChanges = (resolvedMap: Record<string, string>, changes: Change[], format: Formating = DefaultFormating) => {
  const humanizeHistoryChanges = [];
  for (let index = 0; index < changes.length; index++) {
    const change = changes[index];
    const attribute = resolveAttribute(change.field);
    const human = humanizeHistoryChange(resolvedMap, attribute, change, format);
    humanizeHistoryChanges.push(human);
  }
  return humanizeHistoryChanges;
};

export const generateMessageFromChanges = (resolvedMap: Record<string, string>,
  changes: Change[], format: Formating = DefaultFormating): string => {
  const sliceChanges = changes.slice(0, MAX_OPERATIONS_FOR_MESSAGE);
  const actions: Record<string, { message: string; field?: string }[]> = {};
  for (let index = 0; index < sliceChanges.length; index += 1) {
    const historyChange = sliceChanges[index];
    const { field } = historyChange;
    const fieldSplit = field.split('--');
    const key = fieldSplit[1];
    const entityType = fieldSplit[0];
    const attributeDefinition = schemaAttributesDefinition.getAttribute(entityType, key);
    const relationsRefDefinition = schemaRelationsRefDefinition.getRelationRef(entityType, key);
    const attribute = attributeDefinition || relationsRefDefinition;
    const convertChange = (vals?: string[], noValueToEmpty = false): string => {
      const isTooMuch = vals && vals.length > 3;
      const values = isTooMuch ? vals.slice(0, 3) : (vals ?? []);
      if (noValueToEmpty && values.length === 0) return `\`${EMPTY_VALUE}\``;
      return values.map((v) => {
        const val = v.length > MAX_TRANSLATE_LENGTH ? v.slice(0, MAX_TRANSLATE_LENGTH) + '...' : v;
        return `\`${isEmptyField(val) ? EMPTY_VALUE : val}\``;
      }).join(', ') + (isTooMuch ? ', ...' : '');
    };
    const human = humanizeHistoryChange(resolvedMap, attribute, historyChange, format);
    if (attribute?.multiple) {
      if ((human.changes_added ?? []).length > 0) {
        const message = convertChange(human.changes_added);
        if (actions['add']) {
          actions['add'].push({ message, field: attribute?.label });
        } else {
          actions['add'] = [{ message, field: attribute?.label }];
        }
      }
      if ((human.changes_removed ?? []).length > 0) {
        const message = convertChange(human.changes_removed);
        if (actions['removes']) {
          actions['removes'].push({ message, field: attribute?.label });
        } else {
          actions['removes'] = [{ message, field: attribute?.label }];
        }
      }
    } else {
      const message = convertChange(human.changes_added, true);
      if (actions['replaces']) {
        actions['replaces'].push({ message, field: attribute?.label });
      } else {
        actions['replaces'] = [{ message, field: attribute?.label }];
      }
    }
  }
  let newMessage = Object.entries(actions).map(([action, elems]) => {
    return `${action} ${elems.map((e) => `${e.message} in \`${e.field}\``).join(' - ')}`;
  }).join(' | ');
  if (changes.length > MAX_OPERATIONS_FOR_MESSAGE) {
    newMessage += ' and ' + (changes.length - MAX_OPERATIONS_FOR_MESSAGE) + ' more operations';
  }
  return newMessage;
};

export const buildTranslatedIdsMap = (translatedIds: { id: string; source?: string }[],
  resolvedMap: Record<string, string>) => {
  const translatedIdsMap: Record<string, string> = {};
  for (let index = 0; index < translatedIds.length; index += 1) {
    const { id, source } = translatedIds[index];
    const translatedId = source ?? id;
    translatedIdsMap[translatedId] = resolvedMap[translatedId] ?? 'Restricted';
  }
  if (isEmptyField(translatedIdsMap)) {
    return undefined;
  }
  return JSON.stringify(translatedIdsMap);
};

const convertAttribute = async (context: AuthContext, user: AuthUser,
  resolvedMap: Record<string, string>, attribute: AttributeDefinition, item: any): Promise<ChangeValue> => {
  const getEntitiesMapFromCache = buildMapFromCacheContext(context, user);
  // Complex object
  if (attribute.type === 'ref') {
    const translated = { [item.internal_id]: extractEntityRepresentativeName(item) };
    return { raw: item.internal_id, translated: JSON.stringify(translated) };
  }
  if (attribute.type === 'object') {
    const translatedIds = await attribute.attrRawIds?.(item, getEntitiesMapFromCache) ?? [];
    let workItem = item;
    // Specific cleanup for file due to aggressive loading of inner markings
    // Introduced in [backend] fix file markings that could be undefined when building OCTI extensions (#9301)
    // TODO rework this approach to use marking case in converter instead
    if (attribute.name === files.name) {
      const { [INPUT_MARKINGS]: _, ...existingFileWithoutMarkings } = item;
      workItem = existingFileWithoutMarkings;
    }
    return { raw: JSON.stringify(workItem), translated: buildTranslatedIdsMap(translatedIds, resolvedMap) };
  }
  if (attribute.type === 'string' && attribute.format === 'json') {
    const translatedIds = await attribute.attrRawIds?.(item, getEntitiesMapFromCache) ?? [];
    return { raw: item, translated: buildTranslatedIdsMap(translatedIds, resolvedMap) };
  }
  // Native type
  if (attribute.type === 'string') {
    // String representing an id
    if (attribute.format === 'id') {
      const translatedIds = attribute.attrRawIds
        ? await attribute.attrRawIds?.(item, getEntitiesMapFromCache) : [{ id: item }];
      return { raw: item, translated: buildTranslatedIdsMap(translatedIds, resolvedMap) };
    }
    // Other string representation are never translated
    return { raw: item };
  }
  if (attribute.type === 'date') {
    return { raw: utcDate(item).toISOString() };
  }
  if (attribute.type === 'boolean') {
    return { raw: String(item) };
  }
  if (attribute.type === 'numeric') {
    return { raw: String(item) };
  }
  throw UnsupportedError('Change build error, unknown attribute', { attribute });
};

const buildAttribute = async (context: AuthContext, user: AuthUser,
  resolvedMap: Record<string, string>, entityType: string, key: string, values: unknown[]) => {
  const attributeDef = schemaAttributesDefinition.getAttribute(entityType, key);
  const refDef = schemaRelationsRefDefinition.getRelationRef(entityType, key);
  const attribute = attributeDef || refDef;
  if (!attribute) {
    throw UnsupportedError('Unknown attribute', { entityType, key });
  }
  const cleanedValues = values.filter((val) => val !== null && val !== undefined);
  const converted = [];
  for (let i = 0; i < cleanedValues.length; i += 1) {
    const item = cleanedValues[i];
    const attr = await convertAttribute(context, user, resolvedMap, attribute, item);
    converted.push(attr);
  }
  return converted;
};

export const buildChanges = async (context: AuthContext, user: AuthUser,
  entityType: string, inputs: any[]) => {
  // Build the resolution maps converting inputs to changes to use standard resolution function
  const inputsChangesResolver = inputs.flatMap((input) => {
    const { key: field, previous: prevValues, value } = input;
    const ref = schemaRelationsRefDefinition.getRelationRef(entityType, field);
    if (ref) return []; // Ref are already available, no need to extra resolved them.
    const attr = schemaAttributesDefinition.getAttribute(entityType, field);
    if (!attr) throw UnsupportedError('Cant resolve attribute', { entityType, field });
    const prev = Array.isArray(prevValues) ? prevValues : [prevValues];
    const next = Array.isArray(value) ? value : [value];
    const changes_added = [...prev, ...next].filter((i) => isNotEmptyField(i))
      .map((item) => ({ raw: attr.type === 'object' ? JSON.stringify(item) : item }));
    return { field: entityType + '--' + field, changes_added };
  });
  const resolvedMap = inputsChangesResolver.length > 0
    ? await attributesChangesResolver(context, user, [inputsChangesResolver]) : {};
  // Build the changes with raw and translated json map.
  const changes = [];
  for (const input of inputs) {
    const { key: field, previous: prevValues, value, operation } = input;
    if (!field) {
      continue;
    }
    const attributeDefinition = schemaAttributesDefinition.getAttribute(entityType, field);
    const relationsRefDefinition = schemaRelationsRefDefinition.getRelationRef(entityType, field);
    const attribute = attributeDefinition || relationsRefDefinition;
    if (!attribute) {
      throw UnsupportedError('Cant resolve attribute', { entityType, field });
    }
    const isMultiple = attribute.multiple;

    const previousArrayFull = Array.isArray(prevValues) ? prevValues : [prevValues];
    const valueArrayFull = Array.isArray(value) ? value : [value];
    const previous = await buildAttribute(context, user, resolvedMap, entityType, field, previousArrayFull);
    const valueArray = await buildAttribute(context, user, resolvedMap, entityType, field, valueArrayFull);

    const changeField = entityType + '--' + field;
    if (isMultiple) {
      let added: ChangeValue[] = [];
      let removed: ChangeValue[] = [];
      if (operation === UPDATE_OPERATION_ADD) {
        added = valueArray.filter((valueItem) => !previous.find((previousItem) => previousItem.raw === valueItem.raw));
      } else if (operation === UPDATE_OPERATION_REMOVE) {
        removed = valueArray.filter((valueItem) => previous.find((previousItem) => previousItem.raw === valueItem.raw));
      } else { // Replace
        removed = previous.filter((previousItem) => !valueArray.find((valueItem) => previousItem.raw === valueItem.raw));
        added = valueArray.filter((valueItem) => !previous.find((previousItem) => previousItem.raw === valueItem.raw));
      }
      if (added.length > 0 || removed.length > 0) {
        changes.push({
          field: changeField,
          changes_added: added,
          changes_removed: removed,
        });
      }
    } else {
      changes.push({
        field: changeField,
        changes_removed: previous,
        changes_added: valueArray,
      });
    }
  }
  return changes;
};

type LegacyChangeFormat = {
  field: string;
  previous: string[];
  new: string[];
  added: string[];
  removed: string[];
};
const legacyHistoryChanges = (log: any) => {
  const { context_data } = log;
  return context_data.changes.map((change: LegacyChangeFormat) => {
    if (change.new.length > 0) {
      return {
        field: change.field,
        changes_added: change.new,
        changes_removed: change.previous,
      };
    }
    return {
      field: change.field,
      changes_added: change.added,
      changes_removed: change.removed,
    };
  });
};

export const changeIdsExtractor = async (context: AuthContext, user: AuthUser, changes: Change[]) => {
  const ids = [];
  const getEntitiesMapFromCache = buildMapFromCacheContext(context, user);
  for (let index = 0; index < changes.length; index++) {
    const change = changes[index];
    const attribute = resolveAttribute(change.field);
    if (attribute) {
      if (attribute.type === 'ref' || (attribute.type === 'string' && attribute.format === 'id')) {
        const values = (change.changes_added ?? []).map((c) => c.raw);
        values.push(...(change.changes_removed ?? []).map((c) => c.raw));
        for (const v of values) {
          const translatedIds = attribute.attrRawIds
            ? await attribute.attrRawIds?.(v, getEntitiesMapFromCache) : [{ id: v }];
          ids.push(...(translatedIds ?? []));
        }
      }
      if (attribute.type === 'object' || (attribute.type === 'string' && attribute.format === 'json')) {
        const values = (change.changes_added ?? []).map((c) => JSON.parse(c.raw));
        values?.push(...(change.changes_removed ?? []).map((c) => JSON.parse(c.raw)));
        for (const v of values) {
          const translatedIds = await attribute.attrRawIds?.(v, getEntitiesMapFromCache);
          ids.push(...(translatedIds ?? []));
        }
      }
    }
  }
  return ids;
};

const enrichContextDataWithMessageAndChanges = (resolvedMap: Record<string, string>, log: any, args: Formating) => {
  const { context_data } = log;
  // For retro compatibility directly use the message if available
  const historyChanges = context_data.history_changes ?? [];
  const message = historyChanges.length > 0
    ? generateMessageFromChanges(resolvedMap, context_data.history_changes, args) : context_data.message;
    // For retro compatibility use context._data.changes if available
  if (context_data.changes) {
    const changes = legacyHistoryChanges(log);
    return { ...context_data, message, changes, entity_id: log.entity_id ?? log.context_data.id };
  }
  // For new changes format
  const changes = humanizeHistoryChanges(resolvedMap, historyChanges, args);
  return { ...context_data, message, changes, entity_id: log.entity_id ?? log.context_data.id };
};

export const attributesChangesResolver = async (context: AuthContext, user: AuthUser, attributesChanges: Array<Change[]>) => {
  const idsMap: Record<string, string> = {};
  const lookingIds = [];
  for (let index = 0; index < attributesChanges.length; index++) {
    const attributeChanges = attributesChanges[index];
    const idsFromData = await changeIdsExtractor(context, user, attributeChanges);
    for (let i = 0; i < idsFromData.length; i++) {
      const idFromData = idsFromData[i];
      lookingIds.push(idFromData.id);
      idsMap[idFromData.id] = idFromData.source ?? idFromData.id;
    }
  }
  const resolvedMap = await internalFindByIdsMapped(context, user, lookingIds);
  const translatedMap: Record<string, string> = {};
  const entries = Object.entries(resolvedMap);
  for (let entryIndex = 0; entryIndex < entries.length; entryIndex++) {
    const [id, data] = entries[entryIndex];
    const translatedId = idsMap[id];
    translatedMap[translatedId] = extractEntityRepresentativeName(data);
  }
  return translatedMap;
};

export const historyLogsResolver = async (context: AuthContext, user: AuthUser, logs: any[]) => {
  const allChanges = logs.map((log) => log.context_data.history_changes ?? []);
  return attributesChangesResolver(context, user, allChanges);
};

export const batchContextDataForLog = async (context: AuthContext, user: AuthUser, batches: any[]) => {
  const results = [];
  const translatedMap = await historyLogsResolver(context, user, batches.map((b) => b.log));
  for (let index = 0; index < batches.length; index += 1) {
    await doYield();
    const { log, args } = batches[index];
    const contextData = enrichContextDataWithMessageAndChanges(translatedMap, log, args);
    results.push(contextData);
  }
  return results;
};
