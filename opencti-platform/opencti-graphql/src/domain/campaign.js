import { assoc, pipe } from 'ramda';
import {
  createEntity,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  now,
  timeSeriesEntities,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = (campaignId) => {
  if (campaignId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(campaignId, 'Campaign');
  }
  return loadEntityById(campaignId, 'Campaign');
};
export const findAll = (args) => {
  return listEntities(['Campaign'], ['name', 'alias'], args);
};

// region time series
export const campaignsTimeSeries = (args) => {
  return timeSeriesEntities('Campaign', [], args);
};
export const campaignsTimeSeriesByEntity = (args) => {
  const filters = [{ isRelation: true, type: args.relationType, value: args.objectId }];
  return timeSeriesEntities('Campaign', filters, args);
};
// endregion

export const addCampaign = async (user, campaign) => {
  const currentDate = now();
  const campaignToCreate = pipe(
    assoc('first_seen', campaign.first_seen ? campaign.first_seen : currentDate),
    assoc('last_seen', campaign.first_seen ? campaign.first_seen : currentDate)
  )(campaign);
  const created = await createEntity(user, campaignToCreate, 'Campaign');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
