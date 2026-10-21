// Review model of content mapping v2: what the analyst sees in the review panel, computed from
// - content_mapping: { "<mapped text>": "<standard_id>" } (base64 JSON, the mapping itself, exported to STIX),
// - content_mapping_review: ignored values, source and chosen type of each value (base64 JSON, technical),
// - the AI analysis: suggestions of existing objects, and of objects to create (unresolved).
import { entityTypeFamily } from '../../../../utils/Colors';
import { deserializeObjectB64, serializeObjectB64 } from '../../../../utils/object';

export const MAIN_CONTENT_SOURCE = 'main';

export interface ContentMappingReviewState {
  // Suggestions the analyst rejected, kept with what is needed to show and restore them.
  ignored: Record<string, { value: string; entityType: string; standardId?: string }>;
  // Where a value was mapped: the main content or the id of an attached file.
  sources: Record<string, string>;
  // Type chosen by the analyst for a suggestion to create (type correction).
  types: Record<string, string>;
}

export const EMPTY_REVIEW: ContentMappingReviewState = { ignored: {}, sources: {}, types: {} };

// Same encoding as the current content mapping view; an unreadable value is treated as empty.
const decodeB64Json = <T>(value: string | null | undefined, fallback: T): T => {
  try {
    return { ...fallback, ...deserializeObjectB64(value) } as T;
  } catch {
    return fallback;
  }
};

const encodeB64Json = (value: object) => serializeObjectB64(value);

export const decodeMapping = (value: string | null | undefined): Record<string, string> => decodeB64Json(value, {});
export const encodeMapping = (mapping: Record<string, string>) => encodeB64Json(mapping);
export const decodeReview = (value: string | null | undefined): ContentMappingReviewState => ({
  ...EMPTY_REVIEW,
  ...decodeB64Json<Partial<ContentMappingReviewState>>(value, {}),
});
export const encodeReview = (review: ContentMappingReviewState) => encodeB64Json(review);

// Manual mapping stores lowercased keys, suggestions keep their case: values are compared lowercased.
export const mappingKey = (value: string) => value.trim().toLowerCase();

export type ReviewStatus = 'toReview' | 'mapped' | 'ignored';
export type ReviewFamily = 'entities' | 'observables' | 'ttp';

export interface MappableEntity {
  id: string;
  standard_id: string;
  entity_type: string;
  representative?: { main: string } | null;
}

export interface ReviewItem {
  key: string;
  value: string;
  status: ReviewStatus;
  origin: 'manual' | 'ai';
  // An existing object of the platform; otherwise it has to be created on validation.
  entity: MappableEntity | null;
  entityType: string;
  standardId: string | null;
  // The value maps to an object whose name differs (e.g. "U.S." -> United States of America).
  resolvedFrom: string | null;
  // Other types the same name was suggested or exists under.
  duplicateTypes: string[];
  source: string;
}

export interface AnalysisSuggestions {
  mapped: ReadonlyArray<{ matchedString: string; matchedEntity: MappableEntity }>;
  unresolved: ReadonlyArray<{ matchedString: string; standardId: string; entityType: string }>;
}

export const familyOf = (entityType: string): ReviewFamily => {
  const family = entityTypeFamily(entityType);
  if (family === 'observables') return 'observables';
  if (family === 'techniques') return 'ttp';
  return 'entities';
};

const resolvedFrom = (value: string, entity: MappableEntity | null) => {
  const name = entity?.representative?.main;
  return name && mappingKey(name) !== mappingKey(value) ? value : null;
};

export const buildReviewItems = ({ mapping, review, objects, suggestions, suggestionSource = MAIN_CONTENT_SOURCE, existingTypesByName = {} }: {
  mapping: Record<string, string>;
  review: ContentMappingReviewState;
  objects: ReadonlyArray<MappableEntity>;
  suggestions: AnalysisSuggestions;
  // The source the suggestions were extracted from (analysis of the main content or of a file).
  suggestionSource?: string;
  // Types under which objects with the same name already exist in the platform.
  existingTypesByName?: Record<string, string[]>;
}): ReviewItem[] => {
  const byStandardId = new Map(objects.map((o) => [o.standard_id, o]));
  const items = new Map<string, ReviewItem>();
  const sourceOf = (key: string) => review.sources[key] ?? MAIN_CONTENT_SOURCE;

  Object.entries(mapping).forEach(([value, standardId]) => {
    const key = mappingKey(value);
    const entity = byStandardId.get(standardId) ?? null;
    items.set(key, {
      key,
      value,
      status: 'mapped',
      origin: 'manual',
      entity,
      entityType: entity?.entity_type ?? 'Unknown',
      standardId,
      resolvedFrom: resolvedFrom(value, entity),
      duplicateTypes: [],
      source: sourceOf(key),
    });
  });

  const suggestionStatus = (key: string): ReviewStatus => (review.ignored[key] ? 'ignored' : 'toReview');
  suggestions.mapped.forEach(({ matchedString, matchedEntity }) => {
    const key = mappingKey(matchedString);
    if (items.has(key)) return;
    items.set(key, {
      key,
      value: matchedString,
      status: suggestionStatus(key),
      origin: 'ai',
      entity: matchedEntity,
      entityType: matchedEntity.entity_type,
      standardId: matchedEntity.standard_id,
      resolvedFrom: resolvedFrom(matchedString, matchedEntity),
      duplicateTypes: [],
      source: suggestionSource,
    });
  });
  suggestions.unresolved.forEach(({ matchedString, standardId, entityType }) => {
    const key = mappingKey(matchedString);
    if (items.has(key)) return;
    items.set(key, {
      key,
      value: matchedString,
      status: suggestionStatus(key),
      origin: 'ai',
      entity: null,
      entityType: review.types[key] ?? entityType,
      standardId,
      resolvedFrom: null,
      duplicateTypes: [],
      source: suggestionSource,
    });
  });

  // Ignored suggestions stay listed after the analysis is cleared, so that they can be restored.
  Object.entries(review.ignored).forEach(([key, { value, entityType, standardId }]) => {
    if (items.has(key)) return;
    items.set(key, {
      key, value, status: 'ignored', origin: 'ai', entity: null, entityType, standardId: standardId ?? null, resolvedFrom: null, duplicateTypes: [], source: sourceOf(key),
    });
  });

  // Possible duplicates: the same name under several types, in the suggestions or in the platform.
  const typesByName = new Map<string, Set<string>>();
  items.forEach((item) => {
    const name = mappingKey(item.entity?.representative?.main ?? item.value);
    typesByName.set(name, (typesByName.get(name) ?? new Set()).add(item.entityType));
  });
  return [...items.values()].map((item) => {
    const name = mappingKey(item.entity?.representative?.main ?? item.value);
    const types = new Set([...(typesByName.get(name) ?? []), ...(existingTypesByName[name] ?? [])]);
    types.delete(item.entityType);
    return { ...item, duplicateTypes: [...types] };
  });
};

export type ReviewSort = 'status' | 'type' | 'value';

// New objects first (they need the most attention), then by type and value.
export const sortReviewItems = (items: ReviewItem[], sort: ReviewSort) => [...items].sort((a, b) => {
  if (sort === 'status' && !!a.entity !== !!b.entity) return a.entity ? 1 : -1;
  if (sort !== 'value' && a.entityType !== b.entityType) return a.entityType.localeCompare(b.entityType);
  return a.value.localeCompare(b.value);
});

export interface ReviewFilter {
  family: ReviewFamily | 'all';
  duplicatesOnly: boolean;
}

export const filterReviewItems = (items: ReviewItem[], status: ReviewStatus, filter: ReviewFilter) => items
  .filter((item) => item.status === status)
  .filter((item) => filter.family === 'all' || familyOf(item.entityType) === filter.family)
  .filter((item) => !filter.duplicatesOnly || item.duplicateTypes.length > 0);
