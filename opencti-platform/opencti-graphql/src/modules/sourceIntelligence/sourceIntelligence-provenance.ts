import { type BasicStoreEntitySource, SOURCE_KIND_AUTHOR } from './sourceIntelligence-types';

export interface SourceResolver {
  // user id -> source internal ids writing with this user (connectors, feeds, analysts)
  byUser: Map<string, string[]>;
  // author identity id -> source internal id
  byAuthor: Map<string, string>;
}

export const buildSourceResolver = (sources: BasicStoreEntitySource[]): SourceResolver => {
  const byUser = new Map<string, string[]>();
  const byAuthor = new Map<string, string>();
  sources.forEach((source) => {
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
  return { byUser, byAuthor };
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
 * Resolve the sources having written a stored document, one entry per distinct source: its creators (connector, feed
 * and analyst users) and its author. The first creator is dated at creation, the others have no first date (lead time
 * is not computable for them).
 */
export const resolveDocumentAssertions = (doc: ProvenanceDocument, resolver: SourceResolver): ResolvedAssertion[] => {
  const resolved = new Map<string, ResolvedAssertion>();
  const createdAt = toTime(doc.created_at);
  const updatedAt = toTime(doc.updated_at) ?? createdAt;
  asArray(doc.creator_id).forEach((userId, index) => {
    const sourceId = userSource(resolver, userId);
    if (sourceId) {
      mergeAssertion(resolved, { sourceId, firstAt: index === 0 ? createdAt : null, lastAt: updatedAt });
    }
  });
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
  input: { originUserId?: string | null; creatorIds?: string[]; createdByRefId?: string | null },
): string[] => {
  const sources = new Set<string>();
  const users = new Set([...(input.originUserId ? [input.originUserId] : []), ...(input.creatorIds ?? [])]);
  users.forEach((userId) => {
    const sourceId = userSource(resolver, userId);
    if (sourceId) sources.add(sourceId);
  });
  if (input.createdByRefId) {
    const authorSource = resolver.byAuthor.get(input.createdByRefId);
    if (authorSource) sources.add(authorSource);
  }
  return Array.from(sources);
};
