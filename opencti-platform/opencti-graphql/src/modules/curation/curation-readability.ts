import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicConnection, BasicStoreBase, BasicStoreEntity } from '../../types/store';
import { internalFindByIds, pageEntitiesConnection, type EntityOptions } from '../../database/middleware-loader';
import { ES_DEFAULT_PAGINATION } from '../../database/engine';
import { isBypassUser, SYSTEM_USER } from '../../utils/access';

const MAX_PAGE_REFILLS = 5;

/**
 * Proposals and merge records carry the restrictions their participants had at their last refresh (markings and
 * organizations, both enforced by the store, see STIX_ORGANIZATIONS_RESTRICTED), and every participant that exists today
 * can be reclassified before the next one. An element is shown only to users who can read each of its existing
 * participants. A participant that no longer exists (merged away, deleted) leaves the decision to the element's own
 * restrictions.
 */
export const keepWithReadableParticipants = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  elements: T[],
  participantIdsOf: (element: T) => string[],
): Promise<T[]> => {
  if (isBypassUser(user)) return elements;
  const ids = R.uniq(elements.flatMap(participantIdsOf));
  if (ids.length === 0) return elements;
  const found = await internalFindByIds(context, user, ids, { baseData: true }) as BasicStoreBase[];
  const readableIds = new Set(found.map((element) => element.internal_id));
  const unreadableIds = ids.filter((id) => !readableIds.has(id));
  if (unreadableIds.length === 0) return elements;
  const existing = await internalFindByIds(context, SYSTEM_USER, unreadableIds, { baseData: true }) as BasicStoreBase[];
  const hiddenIds = new Set(existing.map((element) => element.internal_id));
  return elements.filter((element) => !participantIdsOf(element).some((id) => hiddenIds.has(id)));
};

/**
 * A page of the elements the user may read. The platform filters and counts them by their stored restrictions; the
 * participant check guards the moments before a refresh, and a page it empties is refilled from the next ones, with
 * the cursor of the last element returned. The total leaves out the rows the check hid on the pages it read; like
 * every counter of the curation hub, it otherwise follows the stored restrictions, which the records manager aligns on
 * the stream event of a reclassification: in the moments before, a total can count a record the user can no longer
 * read, never show any of its content. Checking every participant of every counted record on each count is what this
 * bounded design avoids.
 */
export const pageWithReadableParticipants = async <T extends BasicStoreEntity>(
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  opts: EntityOptions<T>,
  participantIdsOf: (element: T) => string[],
): Promise<BasicConnection<T>> => {
  if (isBypassUser(user)) {
    return pageEntitiesConnection<T>(context, user, [entityType], opts);
  }
  const first = opts.first ?? ES_DEFAULT_PAGINATION;
  const edges: BasicConnection<T>['edges'] = [];
  let hiddenCount = 0;
  let connection = await pageEntitiesConnection<T>(context, user, [entityType], { ...opts, first });
  for (let refill = 0; ; refill += 1) {
    const readable = new Set(await keepWithReadableParticipants(context, user, connection.edges.map((edge) => edge.node), participantIdsOf));
    const pageEdges = connection.edges;
    hiddenCount += pageEdges.filter((edge) => !readable.has(edge.node)).length;
    const kept = pageEdges.filter((edge) => readable.has(edge.node)).slice(0, first - edges.length);
    edges.push(...kept);
    const lastKept = kept.length > 0 ? pageEdges.indexOf(kept[kept.length - 1]) : -1;
    const moreInPage = pageEdges.slice(lastKept + 1).some((edge) => readable.has(edge.node));
    const isFull = edges.length >= first;
    if (isFull || !connection.pageInfo.hasNextPage || refill >= MAX_PAGE_REFILLS) {
      const endCursor = isFull ? edges[edges.length - 1].cursor : (pageEdges[pageEdges.length - 1]?.cursor ?? connection.pageInfo.endCursor);
      const hasNextPage = isFull ? (moreInPage || connection.pageInfo.hasNextPage) : connection.pageInfo.hasNextPage;
      // The elements the participant check hid are not counted: the count matches the rows and reveals none of them.
      const globalCount = Math.max(edges.length, (connection.pageInfo.globalCount ?? 0) - hiddenCount);
      return { edges, pageInfo: { ...connection.pageInfo, endCursor, hasNextPage, globalCount } };
    }
    connection = await pageEntitiesConnection<T>(context, user, [entityType], {
      ...opts,
      first,
      after: connection.pageInfo.endCursor,
    });
  }
};
