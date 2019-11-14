import { assoc, pipe } from 'ramda';
import { createEntity, escapeString, listEntities, loadEntityById, now, timeSeries } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = campaignId => {
  return loadEntityById(campaignId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Campaign'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

// region time series
export const campaignsTimeSeries = args => {
  return timeSeries('match $x isa Campaign', args);
};
export const campaignsTimeSeriesByEntity = args => {
  return timeSeries(
    `match $x isa Campaign;
     $rel($x, $to) isa stix_relation;
     $to has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );
};
// endregion

export const addCampaign = async (user, campaign) => {
  const currentDate = now();
  const campaignToCreate = pipe(
    assoc('first_seen', campaign.first_seen ? campaign.first_seen : currentDate),
    assoc('last_seen', campaign.first_seen ? campaign.first_seen : currentDate)
  )(campaign);
  const created = await createEntity(campaignToCreate, 'Campaign');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
