import { createHash } from 'node:crypto';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import type { EditInput } from '../../generated/graphql';
import {
  type AssertionSource,
  ATTRIBUTE_CONFLICTS,
  MAX_CONFLICT_DISPLAY_LENGTH,
  MAX_CONFLICT_RAW_VALUE_LENGTH,
  PROVENANCE_SIDE_CHANNEL_FIELDS,
  type StoreConflict,
  type StoreConflictValue,
} from './provenance-types';

export interface ConflictAddition {
  field: string;
  value: StoreConflictValue;
}

export interface ConflictRemoval {
  field: string;
  value_hash: string;
}

// Values aligned by the upsert itself (oldest / newest / accumulated), owned by a dedicated engine
// (decay, workflow) or purely technical: a difference is never a source conflict.
const NON_CONFLICTING_FIELDS = new Set([
  'confidence',
  'created',
  'modified',
  'x_opencti_modified_at',
  'start_time',
  'stop_time',
  'first_seen',
  'last_seen',
  'first_observed',
  'last_observed',
  'number_observed',
  'number_seen',
  'max_distinct_count',
  'attribute_count',
  'x_opencti_score',
  'valid_from',
  'valid_until',
  'x_opencti_workflow_id',
  'x_opencti_graph_data',
  'content_mapping',
  'lang',
  ...PROVENANCE_SIDE_CHANNEL_FIELDS,
]);
const NON_CONFLICTING_PREFIXES = ['decay_', 'i_'];

export const isConflictTrackedAttribute = (attribute: AttributeDefinition) => {
  if (attribute.multiple || !attribute.upsert) {
    return false;
  }
  if (attribute.type === 'object' || attribute.type === 'ref') {
    return false;
  }
  if (attribute.type === 'string' && attribute.format === 'json') {
    return false;
  }
  if (NON_CONFLICTING_FIELDS.has(attribute.name)) {
    return false;
  }
  return !NON_CONFLICTING_PREFIXES.some((prefix) => attribute.name.startsWith(prefix));
};

/**
 * Label of a conflicting field as defined by the schema of the element type, the field name when unknown.
 */
export const conflictFieldLabel = (entityType: string | null | undefined, field: string) => {
  return (entityType ? schemaAttributesDefinition.getAttribute(entityType, field)?.label : undefined) ?? field;
};

const isEmptyConflictValue = (value: unknown) => {
  if (value === null || value === undefined) {
    return true;
  }
  return typeof value === 'string' && value.trim().length === 0;
};

export const normalizeConflictValue = (attribute: AttributeDefinition, value: unknown): string | number | boolean => {
  if (attribute.type === 'date') {
    const date = value instanceof Date ? value : new Date(String(value));
    return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
  }
  if (attribute.type === 'numeric') {
    const numeric = Number(value);
    return Number.isNaN(numeric) ? String(value) : numeric;
  }
  if (attribute.type === 'boolean') {
    return value === true || value === 'true';
  }
  return String(value).trim();
};

export const conflictValueHash = (field: string, normalized: string | number | boolean) => {
  return createHash('sha256').update(`${field}:${JSON.stringify(normalized)}`).digest('hex');
};

const truncateDisplay = (display: string) => {
  return display.length > MAX_CONFLICT_DISPLAY_LENGTH ? `${display.substring(0, MAX_CONFLICT_DISPLAY_LENGTH)}...` : display;
};

export const buildConflictValue = (
  attribute: AttributeDefinition,
  value: unknown,
  source: AssertionSource,
  confidence: number | null | undefined,
  at: string,
): StoreConflictValue => {
  const normalized = normalizeConflictValue(attribute, value);
  const raw = JSON.stringify(normalized);
  return {
    value_hash: conflictValueHash(attribute.name, normalized),
    display: truncateDisplay(String(normalized)),
    value: raw.length <= MAX_CONFLICT_RAW_VALUE_LENGTH ? raw : null,
    source_id: source.source_id,
    source_kind: source.source_kind,
    source_name: source.source_name,
    confidence: confidence ?? null,
    last_asserted_at: at,
  };
};

export interface PreviousValueOwner {
  source: AssertionSource;
  confidence: number | null;
}

export interface UpsertConflictsArgs {
  type: string;
  element: Record<string, any>;
  updatePatch: Record<string, any>;
  inputs: EditInput[];
  incomingSource: AssertionSource;
  incomingConfidence: number | null | undefined;
  at: string;
  skipFields?: string[];
  resolvePreviousOwner: (field: string) => Promise<PreviousValueOwner | null>;
}

/**
 * Confidence-based upsert resolution keeps one value per scalar field. Instead of discarding
 * the alternative silently, the losing value is kept as a conflict: the incoming value when it
 * lost, the previous value when the incoming one replaced it.
 */
export const computeUpsertConflicts = async (args: UpsertConflictsArgs) => {
  const { type, element, updatePatch, inputs, incomingSource, incomingConfidence, at, skipFields = [], resolvePreviousOwner } = args;
  const conflictsAdd: ConflictAddition[] = [];
  const conflictsRemove: ConflictRemoval[] = [];
  const attributes = Array.from(schemaAttributesDefinition.getAttributes(type).values());
  for (let index = 0; index < attributes.length; index += 1) {
    const attribute = attributes[index];
    const field = attribute.name;
    if (!(field in updatePatch) || skipFields.includes(field) || !isConflictTrackedAttribute(attribute)) {
      continue;
    }
    const incoming = updatePatch[field];
    const current = element[field];
    if (isEmptyConflictValue(incoming) || isEmptyConflictValue(current)) {
      continue;
    }
    const incomingNormalized = normalizeConflictValue(attribute, incoming);
    const currentNormalized = normalizeConflictValue(attribute, current);
    const incomingHash = conflictValueHash(field, incomingNormalized);
    if (incomingNormalized === currentNormalized) {
      // The value is the current one, it can't stay listed as an alternative.
      conflictsRemove.push({ field, value_hash: incomingHash });
      continue;
    }
    const appliedInput = inputs.find((input) => input.key === field);
    const isIncomingApplied = appliedInput !== undefined && !isEmptyConflictValue(appliedInput.value?.[0])
      && normalizeConflictValue(attribute, appliedInput.value[0]) === incomingNormalized;
    if (isIncomingApplied) {
      const owner = await resolvePreviousOwner(field);
      if (owner) {
        conflictsAdd.push({ field, value: buildConflictValue(attribute, current, owner.source, owner.confidence, at) });
      }
      conflictsRemove.push({ field, value_hash: incomingHash });
    } else {
      conflictsAdd.push({ field, value: buildConflictValue(attribute, incoming, incomingSource, incomingConfidence, at) });
    }
  }
  return { conflictsAdd, conflictsRemove };
};

export interface MergeConflictsArgs<T extends Record<string, any>> {
  type: string;
  target: Record<string, any>;
  sources: T[];
  at: string;
  resolveSourceOwner: (source: T, field: string) => Promise<PreviousValueOwner | null>;
}

/**
 * Merging entities keeps the alternatives of every merged element: the conflicts they held and their
 * values that did not survive. A value equal to the one the merged entity holds is not an alternative:
 * it is never inherited, and the merged entity stops listing it.
 */
export const computeMergeConflicts = async <T extends Record<string, any>>(args: MergeConflictsArgs<T>) => {
  const { type, target, sources, at, resolveSourceOwner } = args;
  const attributes = Array.from(schemaAttributesDefinition.getAttributes(type).values()).filter(isConflictTrackedAttribute);
  const finalValueHashes = new Map<string, string>();
  attributes.forEach((attribute) => {
    const value = target[attribute.name];
    if (!isEmptyConflictValue(value)) {
      finalValueHashes.set(attribute.name, conflictValueHash(attribute.name, normalizeConflictValue(attribute, value)));
    }
  });
  const isFinalValue = (field: string, valueHash: string) => finalValueHashes.get(field) === valueHash;
  const conflictsRemove: ConflictRemoval[] = ((target[ATTRIBUTE_CONFLICTS] ?? []) as StoreConflict[])
    .flatMap((conflict) => (conflict.values ?? [])
      .filter((value) => isFinalValue(conflict.field, value.value_hash))
      .map((value) => ({ field: conflict.field, value_hash: value.value_hash })));
  const conflictsAdd: ConflictAddition[] = sources.flatMap((source) => ((source[ATTRIBUTE_CONFLICTS] ?? []) as StoreConflict[])
    .flatMap((conflict) => (conflict.values ?? [])
      .filter((value) => !isFinalValue(conflict.field, value.value_hash))
      .map((value) => ({ field: conflict.field, value }))));
  for (let sourceIndex = 0; sourceIndex < sources.length; sourceIndex += 1) {
    const source = sources[sourceIndex];
    for (let attributeIndex = 0; attributeIndex < attributes.length; attributeIndex += 1) {
      const attribute = attributes[attributeIndex];
      const sourceValue = source[attribute.name];
      const finalHash = finalValueHashes.get(attribute.name);
      if (finalHash !== undefined && !isEmptyConflictValue(sourceValue)
        && conflictValueHash(attribute.name, normalizeConflictValue(attribute, sourceValue)) !== finalHash) {
        const owner = await resolveSourceOwner(source, attribute.name);
        if (owner) {
          conflictsAdd.push({ field: attribute.name, value: buildConflictValue(attribute, sourceValue, owner.source, owner.confidence, at) });
        }
      }
    }
  }
  return { conflictsAdd, conflictsRemove };
};
