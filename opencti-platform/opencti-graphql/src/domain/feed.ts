import { ENTITY_TYPE_FEED } from '../schema/internalObject';
import { createEntity, deleteElementById } from '../database/middleware';
import { pageEntitiesConnection, storeLoadById } from '../database/middleware-loader';
import type { AuthContext, AuthUser } from '../types/user';
import type { FeedAddInput, MemberAccessInput, QueryFeedsArgs } from '../generated/graphql';
import type { BasicStoreEntityFeed, StoreEntity } from '../types/store';
import { FilterMode } from '../generated/graphql';
import { elReplace } from '../database/engine';
import { FunctionalError, UnsupportedError, ValidationError } from '../config/errors';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { isStixDomainObject } from '../schema/stixDomainObject';
import type { DomainFindById } from './domainTypes';
import { publishUserAction } from '../listener/UserActionListener';
import { isUserHasCapability, SYSTEM_USER, TAXIIAPI_SETCOLLECTIONS } from '../utils/access';
import { TAXIIAPI } from './user';

const VALID_MULTI_MATCH_STRATEGIES = ['first', 'list'];

const checkFeedIntegrity = (input: FeedAddInput) => {
  if (input.separator.length > 1) {
    throw ValidationError('Separator must be only one char', 'separator');
  }
  // Check that every type in feed are correct
  for (let index = 0; index < input.feed_types.length; index += 1) {
    const feedType = input.feed_types[index];
    if (!isStixCyberObservable(feedType) && !isStixDomainObject(feedType)) {
      throw UnsupportedError(`${feedType} is not supported in http feeds`);
    }
    input.feed_attributes.forEach((f) => {
      if (f.multi_match_strategy && !VALID_MULTI_MATCH_STRATEGIES.includes(f.multi_match_strategy)) {
        throw ValidationError(`Invalid multi_match_strategy "${f.multi_match_strategy}", must be "first" or "list"`, 'multi_match_strategy');
      }
      if (f.multi_match_separator && f.multi_match_separator === input.separator) {
        throw ValidationError(
          `Multi-match separator for column "${f.attribute}" must differ from the feed CSV separator ("${input.separator}")`,
          'multi_match_separator',
        );
      }
      if (f.mappings.length !== input.feed_types.length) {
        throw UnsupportedError('Feed mappings length does not match global types length');
      }
      if (!f.mappings.map((m) => m.type).includes(feedType)) {
        throw UnsupportedError(`The mapping of the type ${feedType} is missing in the attribute ${f.attribute}.`);
      }
      if (f.mappings.filter((m) => !input.feed_types.includes(m.type)).length > 0) {
        throw UnsupportedError(`The attribute ${f.attribute} contains an invalid mapping.`);
      }
      f.mappings.forEach((m) => {
        const hasRelType = !!m.relationship_type;
        const hasTargetType = !!m.target_entity_type;
        if (hasRelType !== hasTargetType) {
          throw ValidationError(
            `Mapping for type "${m.type}" in attribute "${f.attribute}": relationship_type and target_entity_type must both be set or both be absent`,
            'feed_attributes',
          );
        }
      });
    });
  }
};

export const createFeed = async (context: AuthContext, user: AuthUser, input: FeedAddInput): Promise<BasicStoreEntityFeed> => {
  checkFeedIntegrity(input);
  const feedToCreate = { ...input, authorized_authorities: [TAXIIAPI_SETCOLLECTIONS] };
  const { element, isCreation } = await createEntity(context, user, feedToCreate, ENTITY_TYPE_FEED, { complete: true });
  if (isCreation) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates csv feed \`${element.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_FEED, input },
    });
  }
  return element;
};
export const findById: DomainFindById<BasicStoreEntityFeed> = async (context: AuthContext, user: AuthUser, feedId: string) => {
  return storeLoadById<BasicStoreEntityFeed>(context, user, feedId, ENTITY_TYPE_FEED);
};
export const editFeed = async (context: AuthContext, user: AuthUser, id: string, input: FeedAddInput): Promise<BasicStoreEntityFeed> => {
  checkFeedIntegrity(input);
  const feed = await findById(context, user, id);
  if (!feed) {
    throw FunctionalError(`Feed ${id} cant be found`);
  }
  // authorized_members renaming
  let finalInput = { ...input };
  if (finalInput.authorized_members) {
    finalInput = { ...finalInput, restricted_members: finalInput.authorized_members } as FeedAddInput & { restricted_members: MemberAccessInput[] };
    delete finalInput.authorized_members;
  }
  await elReplace(feed._index, feed.internal_id, { doc: finalInput });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`configuration\` for csv feed \`${feed.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_FEED, input },
  });
  return findById(context, user, id);
};
export const findFeedPaginated = (context: AuthContext, user: AuthUser, opts: QueryFeedsArgs) => {
  if (user && isUserHasCapability(user, TAXIIAPI)) {
    const options = { ...opts, includeAuthorities: true };
    return pageEntitiesConnection<BasicStoreEntityFeed>(context, user, [ENTITY_TYPE_FEED], options);
  }
  // No user specify, listing only public csv feeds
  const filters = {
    mode: FilterMode.And,
    filterGroups: [],
    filters: [{
      key: ['feed_public'],
      values: ['true'],
    }],
  };
  const publicArgs = { ...(opts ?? {}), filters };
  return pageEntitiesConnection<BasicStoreEntityFeed>(context, SYSTEM_USER, [ENTITY_TYPE_FEED], publicArgs);
};
export const feedDelete = async (context: AuthContext, user: AuthUser, feedId: string) => {
  const deleted = await deleteElementById<StoreEntity>(context, user, feedId, ENTITY_TYPE_FEED);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes csv feed \`${deleted.name}\``,
    context_data: { id: feedId, entity_type: ENTITY_TYPE_FEED, input: deleted },
  });
  return feedId;
};
