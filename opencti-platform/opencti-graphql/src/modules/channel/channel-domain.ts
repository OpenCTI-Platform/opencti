import type { AuthUser } from '../../types/user';
import { createEntity, storeLoadById } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { ChannelAddInput, QueryChannelsArgs } from '../../generated/graphql';
import { listEntitiesPaginated } from '../../database/middleware-loader';
import { BasicStoreEntityChannel, ENTITY_TYPE_CHANNEL } from './channel-types';

export const findById = (user: AuthUser, channelId: string): BasicStoreEntityChannel => {
  return storeLoadById(user, channelId, ENTITY_TYPE_CHANNEL) as unknown as BasicStoreEntityChannel;
};

export const findAll = (user: AuthUser, opts: QueryChannelsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityChannel>(user, [ENTITY_TYPE_CHANNEL], opts);
};

export const addChannel = async (user: AuthUser, channel: ChannelAddInput) => {
  const created = await createEntity(user, channel, ENTITY_TYPE_CHANNEL);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
