import { assoc, pipe, isNil } from 'ramda';
import { createEntity, storeLoadById, timeSeriesEntities } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CAMPAIGN } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { FROM_START, UNTIL_END } from '../utils/format';
import { listEntities } from '../database/middleware-loader';

export const findById = (user, campaignId) => {
  return storeLoadById(user, campaignId, ENTITY_TYPE_CAMPAIGN);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_CAMPAIGN], args);
};

// region time series
export const campaignsTimeSeries = (user, args) => {
  return timeSeriesEntities(user, ENTITY_TYPE_CAMPAIGN, [], args);
};

export const campaignsTimeSeriesByEntity = (user, args) => {
  const filters = [{ isRelation: true, type: args.relationship_type, value: args.objectId }];
  return timeSeriesEntities(user, ENTITY_TYPE_CAMPAIGN, filters, args);
};
// endregion

export const addCampaign = async (user, campaign) => {
  const campaignToCreate = pipe(
    assoc('first_seen', isNil(campaign.first_seen) ? new Date(FROM_START) : campaign.first_seen),
    assoc('last_seen', isNil(campaign.last_seen) ? new Date(UNTIL_END) : campaign.last_seen)
  )(campaign);
  const created = await createEntity(user, campaignToCreate, ENTITY_TYPE_CAMPAIGN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
