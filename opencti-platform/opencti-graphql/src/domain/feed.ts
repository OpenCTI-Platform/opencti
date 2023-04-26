/* eslint-disable camelcase */
import { ENTITY_TYPE_FEED } from '../schema/internalObject';
import { createEntity, deleteElementById } from '../database/middleware';
import { listEntitiesPaginated, storeLoadById } from '../database/middleware-loader';
import type { AuthContext, AuthUser } from '../types/user';
import type { FeedAddInput, QueryFeedsArgs } from '../generated/graphql';
import type { StoreEntityFeed } from '../types/store';
import { elReplace } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { FunctionalError, UnsupportedError, ValidationError } from '../config/errors';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { isStixDomainObject } from '../schema/stixDomainObject';
import type { DomainFindById } from './domainTypes';
import { publishUserAction } from '../listener/UserActionListener';

const checkFeedIntegrity = (input: FeedAddInput) => {
  if (input.separator.length > 1) {
    throw ValidationError('separator', { message: 'Separator must be only one char' });
  }
  // Check that every type in feed are correct
  for (let index = 0; index < input.feed_types.length; index += 1) {
    const feedType = input.feed_types[index];
    if (!isStixCyberObservable(feedType) && !isStixDomainObject(feedType)) {
      throw UnsupportedError(`${feedType} is not supported in http feeds`);
    }
    input.feed_attributes.forEach((f) => {
      if (f.mappings.length !== input.feed_types.length) {
        throw UnsupportedError('Feed mappings length does not match global types length');
      }
      if (!f.mappings.map((m) => m.type).includes(feedType)) {
        throw UnsupportedError(`The mapping of the type ${feedType} is missing in the attribute ${f.attribute}.`);
      }
      if (f.mappings.filter((m) => !input.feed_types.includes(m.type)).length > 0) {
        throw UnsupportedError(`The attribute ${f.attribute} contains an invalid mapping.`);
      }
    });
  }
};

export const createFeed = async (context: AuthContext, user: AuthUser, input: FeedAddInput): Promise<StoreEntityFeed> => {
  checkFeedIntegrity(input);
  const { element, isCreation } = await createEntity(context, user, input, ENTITY_TYPE_FEED, { complete: true });
  if (isCreation) {
    await publishUserAction({
      user,
      event_type: 'admin',
      status: 'success',
      message: `creates csv feed \`${element.name}\``,
      context_data: { entity_type: ENTITY_TYPE_FEED, operation: 'create', input }
    });
  }
  return element;
};
export const findById: DomainFindById<StoreEntityFeed> = async (context: AuthContext, user: AuthUser, feedId: string) => {
  return storeLoadById<StoreEntityFeed>(context, user, feedId, ENTITY_TYPE_FEED);
};
export const editFeed = async (context: AuthContext, user: AuthUser, id: string, input: FeedAddInput): Promise<StoreEntityFeed> => {
  checkFeedIntegrity(input);
  const feed = await findById(context, user, id);
  if (!feed) {
    throw FunctionalError(`Feed ${id} cant be found`);
  }
  await elReplace(INDEX_INTERNAL_OBJECTS, id, { doc: input });
  await publishUserAction({
    user,
    event_type: 'admin',
    status: 'success',
    message: `updates \`configuration\` for csv feed \`${feed.name}\``,
    context_data: { entity_type: ENTITY_TYPE_FEED, operation: 'update', input }
  });
  return findById(context, user, id);
};
export const findAll = (context: AuthContext, user: AuthUser, opts: QueryFeedsArgs) => {
  return listEntitiesPaginated<StoreEntityFeed>(context, user, [ENTITY_TYPE_FEED], opts);
};
export const feedDelete = async (context: AuthContext, user: AuthUser, feedId: string) => {
  const deleted = await deleteElementById(context, user, feedId, ENTITY_TYPE_FEED);
  await publishUserAction({
    user,
    event_type: 'admin',
    status: 'success',
    message: `deletes csv feed \`${deleted.name}\``,
    context_data: { entity_type: ENTITY_TYPE_FEED, operation: 'delete', input: deleted }
  });
  return feedId;
};
