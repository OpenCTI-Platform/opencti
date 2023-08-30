import { assoc, isNil, pipe } from 'ramda';
import { createEntity, timeSeriesEntities } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CAMPAIGN } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { FROM_START, UNTIL_END } from '../utils/format';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { addFilter } from '../utils/filtering';

export const findById = (context, user, campaignId) => {
  return storeLoadById(context, user, campaignId, ENTITY_TYPE_CAMPAIGN);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_CAMPAIGN], args);
};

// region time series
export const campaignsTimeSeries = (context, user, args) => {
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CAMPAIGN], args);
};

export const campaignsTimeSeriesByEntity = (context, user, args) => {
  const { relationship_type, objectId } = args;
  const filters = addFilter(args.filters, relationship_type.map((n) => buildRefRelationKey(n, '*')), objectId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CAMPAIGN], { ...args, filters });
};
// endregion

export const addCampaign = async (context, user, campaign) => {
  const campaignToCreate = pipe(
    assoc('first_seen', isNil(campaign.first_seen) ? new Date(FROM_START) : campaign.first_seen),
    assoc('last_seen', isNil(campaign.last_seen) ? new Date(UNTIL_END) : campaign.last_seen)
  )(campaign);
  const created = await createEntity(context, user, campaignToCreate, ENTITY_TYPE_CAMPAIGN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
