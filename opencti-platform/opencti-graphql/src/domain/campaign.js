import { assoc, pipe, isNil } from 'ramda';
import { createEntity, listEntities, loadById, timeSeriesEntities, FROM_START, UNTIL_END } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CAMPAIGN } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (campaignId) => {
  return loadById(campaignId, ENTITY_TYPE_CAMPAIGN);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_CAMPAIGN], args);
};

// region time series
export const campaignsTimeSeries = (args) => {
  return timeSeriesEntities(ENTITY_TYPE_CAMPAIGN, [], args);
};

export const campaignsTimeSeriesByEntity = (args) => {
  const filters = [{ isRelation: true, type: args.relationship_type, value: args.objectId }];
  return timeSeriesEntities(ENTITY_TYPE_CAMPAIGN, filters, args);
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
