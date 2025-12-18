import { extractEntityRepresentativeName } from './entity-representative';
import { isStixObject } from '../schema/stixCoreObject';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../schema/stixCyberObservable';
import { isBasicRelationship } from '../schema/stixRelationship';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, isEmptyField } from './utils';
import { isStoreRelationPir } from '../schema/internalRelationship';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import type { Change, ChangeValue, HumanChange } from '../types/event';
import { type AttributeDefinition } from '../schema/attribute-definition';
import { DefaultFormating, type Formating, humanizeDate } from '../utils/humanize';

export const EMPTY_VALUE = 'nothing';
const MAX_TRANSLATE_LENGTH = 50;
const MAX_OPERATIONS_FOR_MESSAGE = 3;

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

const humanizeRawValue = (attribute: AttributeDefinition, v: ChangeValue, format: Formating = DefaultFormating) => {
  const targetValue = v.raw;
  if (attribute?.type === 'date') {
    return humanizeDate(targetValue, format);
  }
  if (attribute?.type === 'string') {
    if (attribute.format === 'id' || attribute.format === 'json') {
      try {
        const translated = JSON.parse(v.translated ?? '{}');
        return attribute.representative?.(v.raw, translated, format) ?? v.raw;
      } catch {
        return v.raw;
      }
    }
    if (attribute.format === 'text' && v.raw.length > MAX_TRANSLATE_LENGTH) {
      return `${v.raw.slice(0, MAX_TRANSLATE_LENGTH)}...`;
    }
    return isEmptyField(v.raw) ? EMPTY_VALUE : v.raw; // vocab / enum
  }
  if (attribute?.type === 'boolean') {
    return v.raw === 'true' ? 'Yes' : 'No';
  }
  if (attribute?.type === 'numeric') {
    return v.raw;
  }
  if (attribute?.type === 'object') {
    try {
      const translated = JSON.parse(v.translated ?? '{}');
      return attribute.representative?.(JSON.parse(v.raw), translated, format) ?? v.raw;
    } catch {
      return v.raw;
    }
  }
  if (attribute?.type === 'ref') {
    try {
      const translated = JSON.parse(v.translated ?? '{}');
      return translated?.[v.raw];
    } catch {
      return v.translated;
    }
  }
  return v.raw;
};

const humanizeChangeValues = (field: string, changeValues: ChangeValue[] | undefined, format: Formating = DefaultFormating): HumanChange[] => {
  const attribute = resolveAttribute(field);
  return (changeValues ?? []).map((v) => ({ raw: v.raw, human: attribute ? humanizeRawValue(attribute, v, format) : '{{unknown}}' } as HumanChange));
};

export const humanizeHistoryChange = (attribute: AttributeDefinition | null, change: Change, format: Formating = DefaultFormating) => {
  return {
    field: attribute?.label ?? change.field,
    changes_added: humanizeChangeValues(change.field, change.changes_added, format),
    changes_removed: humanizeChangeValues(change.field, change.changes_removed, format),
  };
};

export const humanizeHistoryChanges = (changes: Change[], format: Formating = DefaultFormating) => {
  return changes.map((change) => {
    const attribute = resolveAttribute(change.field);
    return humanizeHistoryChange(attribute, change, format);
  });
};

export const generateMessageFromChanges = (changes: Change[], format: Formating = DefaultFormating): string => {
  const sliceChanges = changes.slice(0, MAX_OPERATIONS_FOR_MESSAGE);
  const actions: Record<string, { message: string; field?: string }[]> = {};
  sliceChanges.forEach((historyChange) => {
    const { field } = historyChange;
    const fieldSplit = field.split('--');
    const key = fieldSplit[1];
    const entityType = fieldSplit[0];
    const attributeDefinition = schemaAttributesDefinition.getAttribute(entityType, key);
    const relationsRefDefinition = schemaRelationsRefDefinition.getRelationRef(entityType, key);
    const attribute = attributeDefinition || relationsRefDefinition;
    const convertChange = (vals?: HumanChange[]): string => {
      const isTooMuch = vals && vals.length > 3;
      const values = isTooMuch ? vals.slice(0, 3) : (vals ?? []);
      return values.map((v) => `\`${v.human || v.raw}\``).join(', ') + (isTooMuch ? ', ...' : '');
    };
    const human = humanizeHistoryChange(attribute, historyChange, format);
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
      const message = convertChange(human.changes_added);
      if (actions['replaces']) {
        actions['replaces'].push({ message, field: attribute?.label });
      } else {
        actions['replaces'] = [{ message, field: attribute?.label }];
      }
    }
  });
  let newMessage = Object.entries(actions).map(([action, elems]) => {
    return `${action} ${elems.map((e) => `${e.message} in \`${e.field}\``).join(' - ')}`;
  }).join(' | ');
  if (changes.length > MAX_OPERATIONS_FOR_MESSAGE) {
    newMessage += ' and ' + (changes.length - MAX_OPERATIONS_FOR_MESSAGE) + ' more operations';
  }
  return newMessage;
};
