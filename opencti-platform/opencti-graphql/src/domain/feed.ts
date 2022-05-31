/* eslint-disable camelcase */
import { ENTITY_TYPE_FEED } from '../schema/internalObject';
import { createEntity, deleteElementById, storeLoadById } from '../database/middleware';
import { listEntitiesPaginated } from '../database/middleware-loader';
import type { AuthUser } from '../types/user';
import type { FeedAddInput, QueryFeedsArgs } from '../generated/graphql';
import type { StoreEntityFeed } from '../types/store';
import { elReplace } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { FunctionalError, UnsupportedError, ValidationError } from '../config/errors';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { isStixDomainObject } from '../schema/stixDomainObject';

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

export const createFeed = async (user: AuthUser, input: FeedAddInput): Promise<StoreEntityFeed> => {
  checkFeedIntegrity(input);
  return createEntity(user, input, ENTITY_TYPE_FEED);
};
export const findById = async (user: AuthUser, feedId: string): Promise<StoreEntityFeed> => {
  return storeLoadById(user, feedId, ENTITY_TYPE_FEED) as unknown as StoreEntityFeed;
};
export const editFeed = async (user: AuthUser, id: string, input: FeedAddInput): Promise<StoreEntityFeed> => {
  checkFeedIntegrity(input);
  const feed = await findById(user, id);
  if (!feed) {
    throw FunctionalError(`Feed ${id} cant be found`);
  }
  await elReplace(INDEX_INTERNAL_OBJECTS, id, { doc: input });
  return findById(user, id);
};
export const findAll = (user: AuthUser, opts: QueryFeedsArgs) => {
  return listEntitiesPaginated<StoreEntityFeed>(user, [ENTITY_TYPE_FEED], opts);
};
export const feedDelete = async (user: AuthUser, feedId: string) => {
  await deleteElementById(user, feedId, ENTITY_TYPE_FEED);
  return feedId;
};
