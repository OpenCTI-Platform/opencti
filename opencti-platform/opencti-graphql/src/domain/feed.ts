/* eslint-disable camelcase */
import { ENTITY_TYPE_FEED } from '../schema/internalObject';
import { createEntity, deleteElementById, storeLoadById } from '../database/middleware';
import { listEntitiesPaginated } from '../database/middleware-loader';
import type { AuthUser } from '../types/user';
import type { FeedAddInput, QueryFeedsArgs } from '../generated/graphql';
import type { StoreEntityFeed } from '../types/store';
import { elReplace } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { isStixDomainObject } from '../schema/stixDomainObject';

const checkFeedIntegrity = (input: FeedAddInput) => {
  // Check that every type in feed are correct
  for (let index = 0; index < input.feed_types.length; index += 1) {
    const feedType = input.feed_types[index];
    if (!isStixCyberObservable(feedType) && !isStixDomainObject(feedType)) {
      throw UnsupportedError(`${feedType} is not supported in http feeds`);
    }
  }
  // Check that attributes are mapped correctly
  for (let index = 0; index < input.feed_types.length; index += 1) {
    const mappingTypes = input.feed_attributes.map((a) => a.mappings).flat().map((m) => m.type);
    if (mappingTypes.length !== input.feed_types.length) {
      throw UnsupportedError('Feed is not mapped correctly');
    }
    mappingTypes.forEach((a) => {
      if (!input.feed_types.includes(a)) {
        throw UnsupportedError(`${a} cannot be used in mapping without global definition`);
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
