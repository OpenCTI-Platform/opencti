import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import {
  type BasicStoreEntitySource,
  type ProvenanceMode,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_CONNECTOR,
  SOURCE_KIND_INGESTION_FEED,
  SOURCE_KIND_MANUAL,
  type SourceKindValue,
} from './sourceIntelligence-types';

// Provenance attribute owned by innovation 06 (Provenance, Corroboration and Freshness), see its plan section 5:
// x_opencti_assertions: [{ source_id, source_kind, source_name, first_asserted_at, last_asserted_at, assert_count, confidence, work_id }]
export const PROVENANCE_ATTRIBUTE = 'x_opencti_assertions';
export const PROVENANCE_LAST_ASSERTED_AT = 'last_asserted_at';
export const PROVENANCE_CORROBORATION_COUNT = 'corroboration_count';

export interface ProvenanceAssertion {
  source_id: string;
  source_kind: string;
  source_name?: string;
  first_asserted_at?: string | null;
  last_asserted_at?: string | null;
  assert_count?: number;
  confidence?: number;
  work_id?: string | null;
}

// Assertion kinds of innovation 06 mapped to source kinds; inference and emulation are not intelligence sources
export const ASSERTION_KIND_TO_SOURCE_KIND: Record<string, SourceKindValue> = {
  connector: SOURCE_KIND_CONNECTOR,
  feed: SOURCE_KIND_INGESTION_FEED,
  author: SOURCE_KIND_AUTHOR,
  user: SOURCE_KIND_MANUAL,
};

export const isProvenanceAttributeAvailable = (): boolean => {
  return schemaAttributesDefinition.getAttributeByName(PROVENANCE_ATTRIBUTE) !== undefined;
};

export const resolveProvenanceMode = (): ProvenanceMode => (isProvenanceAttributeAvailable() ? 'assertions' : 'creators');

export interface SourceResolver {
  // `${source_kind}|${ref_id}` -> source internal id
  byRef: Map<string, string>;
  // user id -> source internal ids writing with this user (connectors, feeds, analysts)
  byUser: Map<string, string[]>;
  // author identity id -> source internal id
  byAuthor: Map<string, string>;
}

export const sourceRefKey = (kind: string, refId: string) => `${kind}|${refId}`;

export const buildSourceResolver = (sources: BasicStoreEntitySource[], aliases: Array<{ kind: SourceKindValue; refId: string; sourceId: string }> = []): SourceResolver => {
  const byRef = new Map<string, string>();
  const byUser = new Map<string, string[]>();
  const byAuthor = new Map<string, string>();
  sources.forEach((source) => {
    byRef.set(sourceRefKey(source.source_kind, source.ref_id), source.internal_id);
    if (source.source_kind === SOURCE_KIND_AUTHOR) {
      byAuthor.set(source.ref_id, source.internal_id);
    }
    (source.source_user_ids ?? []).forEach((userId) => {
      const current = byUser.get(userId) ?? [];
      if (!current.includes(source.internal_id)) {
        byUser.set(userId, [...current, source.internal_id]);
      }
    });
  });
  aliases.forEach(({ kind, refId, sourceId }) => byRef.set(sourceRefKey(kind, refId), sourceId));
  return { byRef, byUser, byAuthor };
};

/**
 * The source writing with a user, when it is the only one: a user shared by several connectors or feeds does not tell
 * which of them wrote, so it credits none of them rather than all of them (no artificial corroboration or overlap).
 */
export const userSource = (resolver: SourceResolver, userId: string): string | undefined => {
  const sources = resolver.byUser.get(userId) ?? [];
  return sources.length === 1 ? sources[0] : undefined;
};

export interface ProvenanceDocument {
  internal_id: string;
  created_at?: string;
  updated_at?: string;
  creator_id?: string[] | string;
  'rel_created-by.internal_id'?: string[] | string;
  x_opencti_assertions?: ProvenanceAssertion[] | ProvenanceAssertion | null;
}

export interface ResolvedAssertion {
  sourceId: string;
  firstAt: number | null;
  lastAt: number | null;
}

const toTime = (value: string | null | undefined): number | null => {
  if (!value) {
    return null;
  }
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? time : null;
};

const asArray = <T>(value: T[] | T | null | undefined): T[] => {
  if (value === null || value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

const mergeAssertion = (target: Map<string, ResolvedAssertion>, assertion: ResolvedAssertion) => {
  const existing = target.get(assertion.sourceId);
  if (!existing) {
    target.set(assertion.sourceId, assertion);
    return;
  }
  const firstCandidates = [existing.firstAt, assertion.firstAt].filter((t): t is number => t !== null);
  const lastCandidates = [existing.lastAt, assertion.lastAt].filter((t): t is number => t !== null);
  target.set(assertion.sourceId, {
    sourceId: assertion.sourceId,
    firstAt: firstCandidates.length > 0 ? Math.min(...firstCandidates) : null,
    lastAt: lastCandidates.length > 0 ? Math.max(...lastCandidates) : null,
  });
};

/**
 * Resolve the sources having asserted a stored document, one entry per distinct source.
 * - With the provenance attribute of innovation 06, every assertion carries its own first / last assertion dates.
 * - Without it (or for documents not yet backfilled), the creators (connector, feed and analyst users) and the author
 *   are used: the first creator is dated at creation, the others have no first date (lead time is not computable).
 * The author (createdBy) is always resolved, even when the assertions do not carry an author entry.
 */
export const resolveDocumentAssertions = (doc: ProvenanceDocument, resolver: SourceResolver): ResolvedAssertion[] => {
  const resolved = new Map<string, ResolvedAssertion>();
  const createdAt = toTime(doc.created_at);
  const updatedAt = toTime(doc.updated_at) ?? createdAt;
  const assertions = asArray(doc.x_opencti_assertions);
  if (assertions.length > 0) {
    assertions.forEach((assertion) => {
      const kind = ASSERTION_KIND_TO_SOURCE_KIND[assertion.source_kind];
      if (!kind || !assertion.source_id) {
        return;
      }
      const sourceId = resolver.byRef.get(sourceRefKey(kind, assertion.source_id));
      if (sourceId) {
        mergeAssertion(resolved, {
          sourceId,
          firstAt: toTime(assertion.first_asserted_at),
          lastAt: toTime(assertion.last_asserted_at) ?? toTime(assertion.first_asserted_at),
        });
      }
    });
  } else {
    asArray(doc.creator_id).forEach((userId, index) => {
      const sourceId = userSource(resolver, userId);
      if (sourceId) {
        mergeAssertion(resolved, { sourceId, firstAt: index === 0 ? createdAt : null, lastAt: updatedAt });
      }
    });
  }
  asArray(doc['rel_created-by.internal_id']).forEach((authorId) => {
    const sourceId = resolver.byAuthor.get(authorId);
    if (sourceId && !resolved.has(sourceId)) {
      mergeAssertion(resolved, { sourceId, firstAt: createdAt, lastAt: updatedAt });
    }
  });
  return Array.from(resolved.values());
};

/**
 * Resolve the sources of a stream event (STIX representation): the user at the origin of the event and the author.
 */
export const resolveEventSources = (
  resolver: SourceResolver,
  input: { originUserId?: string | null; creatorIds?: string[]; createdByRefId?: string | null; assertions?: ProvenanceAssertion[] | null },
): string[] => {
  const sources = new Set<string>();
  const assertions = input.assertions ?? [];
  if (assertions.length > 0) {
    assertions.forEach((assertion) => {
      const kind = ASSERTION_KIND_TO_SOURCE_KIND[assertion.source_kind];
      const sourceId = kind ? resolver.byRef.get(sourceRefKey(kind, assertion.source_id)) : undefined;
      if (sourceId) sources.add(sourceId);
    });
  } else {
    const users = new Set([...(input.originUserId ? [input.originUserId] : []), ...(input.creatorIds ?? [])]);
    users.forEach((userId) => {
      const sourceId = userSource(resolver, userId);
      if (sourceId) sources.add(sourceId);
    });
  }
  if (input.createdByRefId) {
    const authorSource = resolver.byAuthor.get(input.createdByRefId);
    if (authorSource) sources.add(authorSource);
  }
  return Array.from(sources);
};
