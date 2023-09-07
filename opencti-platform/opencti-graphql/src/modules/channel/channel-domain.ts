import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { ChannelAddInput, QueryChannelsArgs } from '../../generated/graphql';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityChannel, ENTITY_TYPE_CHANNEL } from './channel-types';

export const findById = (context: AuthContext, user: AuthUser, channelId: string): BasicStoreEntityChannel => {
  return storeLoadById(context, user, channelId, ENTITY_TYPE_CHANNEL) as unknown as BasicStoreEntityChannel;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryChannelsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityChannel>(context, user, [ENTITY_TYPE_CHANNEL], opts);
};

export const addChannel = async (context: AuthContext, user: AuthUser, channel: ChannelAddInput) => {
  const created = await createEntity(context, user, channel, ENTITY_TYPE_CHANNEL);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
