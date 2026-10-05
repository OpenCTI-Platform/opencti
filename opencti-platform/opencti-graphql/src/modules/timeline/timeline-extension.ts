import { cleanObject } from '../../database/stix-converter-utils';
import {
  type StixTimelineExtension,
  type StixTimelineExtensionAnnotation,
  type StixTimelineExtensionEvent,
  type StoreTimelineExchange,
  TIMELINE_CLEARABLE_ANALYST_FIELDS,
  TIMELINE_KINDS,
  TIMELINE_LANES,
  TIMELINE_PRECISIONS,
  type TimelineKindValue,
  type TimelineLaneValue,
  type TimelinePrecisionValue,
} from './timeline-types';

/**
 * Build the timeline STIX extension from the analyst contributions denormalized on a container.
 * Returns undefined when there is nothing to carry, so that containers without contributions
 * keep exactly the same STIX representation as before the timeline existed.
 */
export const buildStixTimelineExtension = (exchange: StoreTimelineExchange | null | undefined): StixTimelineExtension | undefined => {
  if (!exchange) return undefined;
  const events = exchange.events ?? [];
  const annotations = exchange.annotations ?? [];
  if (events.length === 0 && annotations.length === 0) return undefined;
  return {
    extension_type: 'property-extension',
    events: events.map((event) => cleanObject({ ...event })),
    annotations: annotations.map((annotation) => cleanObject({ ...annotation })),
  };
};

// Same bounds as the timeline mutations (GraphQL constraints and Int range)
const TITLE_MAX_LENGTH = 512;
const TEXT_MAX_LENGTH = 10000;
const EXTERNAL_ID_MAX_LENGTH = 256;
const GRAPHQL_INT_MIN = -(2 ** 31);
const GRAPHQL_INT_MAX = 2 ** 31 - 1;

const LANES = new Set<string>(TIMELINE_LANES);
const PRECISIONS = new Set<string>(TIMELINE_PRECISIONS);
const KINDS = new Set<string>(TIMELINE_KINDS);
const CLEARABLE_FIELDS: readonly unknown[] = TIMELINE_CLEARABLE_ANALYST_FIELDS;

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const asString = (value: unknown): string | undefined => (typeof value === 'string' && value.trim().length > 0 ? value : undefined);
const asText = (value: unknown, maxLength: number): string | undefined => (typeof value === 'string' ? value.slice(0, maxLength) : undefined);
const asTime = (value: unknown): string | undefined => {
  if (typeof value !== 'string') return undefined;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? undefined : value;
};
const asInteger = (value: unknown, min: number, max: number): number | undefined => {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max ? value : undefined;
};
const asBoolean = (value: unknown): boolean | undefined => (typeof value === 'boolean' ? value : undefined);

export interface SanitizedTimelineExtension {
  events: StixTimelineExtensionEvent[];
  annotations: StixTimelineExtensionAnnotation[];
  /** Contributions dropped because they cannot be identified or placed in time */
  dropped: number;
  /** Values replaced because they were unknown or out of bounds */
  normalized: number;
}

/**
 * Validate a timeline extension received from outside (the extension is opaque JSON, so neither
 * the GraphQL enums nor the input constraints protect it). Unknown lanes, kinds and precisions are
 * mapped to the manual-event defaults ("custom", "milestone") and to "approximate" (a time whose
 * precision is unknown is never presented as exact); malformed optional values are removed.
 * Events without an identifier, a title or a valid start time, and annotations that cannot target
 * a derived event, are dropped. Only the first `limits.maxEvents` events and `limits.maxAnnotations`
 * annotations are read, the others are dropped.
 */
export const sanitizeTimelineExtension = (
  extension: unknown,
  limits: { maxEvents: number; maxAnnotations: number },
): SanitizedTimelineExtension => {
  let dropped = 0;
  let normalized = 0;
  const pick = <T extends string>(value: unknown, allowed: Set<string>, whenAbsent: T, whenUnknown: T): T => {
    if (value === undefined || value === null) return whenAbsent;
    if (allowed.has(value as string)) return value as T;
    normalized += 1;
    return whenUnknown;
  };
  const source = isObject(extension) ? extension : {};
  const allEvents = Array.isArray(source.events) ? source.events : [];
  const allAnnotations = Array.isArray(source.annotations) ? source.annotations : [];
  const rawEvents = allEvents.slice(0, Math.max(0, limits.maxEvents));
  const rawAnnotations = allAnnotations.slice(0, Math.max(0, limits.maxAnnotations));
  dropped += (allEvents.length - rawEvents.length) + (allAnnotations.length - rawAnnotations.length);
  const events: StixTimelineExtensionEvent[] = [];
  rawEvents.forEach((raw) => {
    const id = isObject(raw) ? asString(raw.id) : undefined;
    const rawExternalId = isObject(raw) ? asString(raw.external_id) : undefined;
    // An overlong idempotency key is dropped, never cut: two keys sharing their first characters must not merge
    const externalId = rawExternalId && rawExternalId.length <= EXTERNAL_ID_MAX_LENGTH ? rawExternalId : undefined;
    const title = isObject(raw) ? asString(raw.title) : undefined;
    const eventTime = isObject(raw) ? asTime(raw.event_time) : undefined;
    if (!isObject(raw) || !(id ?? externalId) || !title || !eventTime) {
      dropped += 1;
      return;
    }
    let eventEndTime = asTime(raw.event_end_time);
    if (eventEndTime && new Date(eventEndTime).getTime() <= new Date(eventTime).getTime()) eventEndTime = undefined;
    const lane = pick<TimelineLaneValue>(raw.lane, LANES, 'custom', 'custom');
    const kind = pick<TimelineKindValue>(raw.kind, KINDS, 'milestone', 'milestone');
    const precision = pick<TimelinePrecisionValue>(raw.precision, PRECISIONS, 'exact', 'approximate');
    const confidence = asInteger(raw.confidence, 0, 100);
    const orderingHint = asInteger(raw.ordering_hint, GRAPHQL_INT_MIN, GRAPHQL_INT_MAX);
    const markingRefs = Array.isArray(raw.object_marking_refs) ? raw.object_marking_refs.filter((ref): ref is string => !!asString(ref)) : undefined;
    const optionalDropped = [
      raw.event_end_time !== undefined && raw.event_end_time !== null && !eventEndTime,
      raw.confidence !== undefined && raw.confidence !== null && confidence === undefined,
      raw.ordering_hint !== undefined && raw.ordering_hint !== null && orderingHint === undefined,
      raw.object_marking_refs !== undefined && (!markingRefs || markingRefs.length !== (raw.object_marking_refs as unknown[]).length),
      raw.pinned !== undefined && raw.pinned !== null && asBoolean(raw.pinned) === undefined,
      raw.hidden !== undefined && raw.hidden !== null && asBoolean(raw.hidden) === undefined,
      title.length > TITLE_MAX_LENGTH,
      rawExternalId !== undefined && externalId === undefined,
    ].filter(Boolean).length;
    normalized += optionalDropped;
    events.push(cleanObject({
      id: id ?? externalId as string,
      external_id: externalId,
      event_time: eventTime,
      event_end_time: eventEndTime,
      precision,
      lane,
      kind,
      title: title.slice(0, TITLE_MAX_LENGTH),
      description: asText(raw.description, TEXT_MAX_LENGTH),
      element_ref: asString(raw.element_ref),
      confidence,
      ordering_hint: orderingHint,
      pinned: asBoolean(raw.pinned),
      hidden: asBoolean(raw.hidden),
      annotation: asText(raw.annotation, TEXT_MAX_LENGTH),
      object_marking_refs: markingRefs,
      created_by_ref: asString(raw.created_by_ref),
    }));
  });
  const annotations: StixTimelineExtensionAnnotation[] = [];
  rawAnnotations.forEach((raw) => {
    const ruleId = isObject(raw) ? asString(raw.rule_id) : undefined;
    const elementRef = isObject(raw) ? asString(raw.element_ref) : undefined;
    if (!isObject(raw) || !ruleId || !elementRef || !KINDS.has(raw.kind as string)) {
      dropped += 1;
      return;
    }
    const annotation = asText(raw.annotation, TEXT_MAX_LENGTH);
    const orderingHint = asInteger(raw.ordering_hint, GRAPHQL_INT_MIN, GRAPHQL_INT_MAX);
    const rawCleared = Array.isArray(raw.cleared_fields) ? raw.cleared_fields : [];
    // A field carried with a value is set, never cleared
    const cleared = TIMELINE_CLEARABLE_ANALYST_FIELDS.filter((field) => rawCleared.includes(field)
      && (field === 'annotation' ? annotation === undefined : orderingHint === undefined));
    if (raw.cleared_fields !== undefined && (!Array.isArray(raw.cleared_fields) || rawCleared.some((field) => !CLEARABLE_FIELDS.includes(field)))) {
      normalized += 1;
    }
    annotations.push(cleanObject({
      rule_id: ruleId,
      kind: raw.kind as TimelineKindValue,
      element_ref: elementRef,
      pinned: asBoolean(raw.pinned),
      hidden: asBoolean(raw.hidden),
      annotation,
      ordering_hint: orderingHint,
      cleared_fields: cleared,
    }));
  });
  return { events, annotations, dropped, normalized };
};
