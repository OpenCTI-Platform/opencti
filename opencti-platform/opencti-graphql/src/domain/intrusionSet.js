import { assoc, isNil, pipe } from 'ramda';
import { createEntity } from '../database/middleware';
import { listEntities, listEntitiesThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_INTRUSION_SET } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_LOCATION } from '../schema/general';
import { RELATION_ORIGINATES_FROM } from '../schema/stixCoreRelationship';
import { FROM_START, minutesAgo, monthsAgo, now, UNTIL_END, utcDate } from '../utils/format';
import { getIndicatorsStats, getTopVictims, getVictimologyStats, systemPrompt } from '../utils/ai/summaryHelpers';
import { queryAi } from '../database/ai-llm';

const aiResponseCache = {};

export const findById = (context, user, intrusionSetId) => {
  return storeLoadById(context, user, intrusionSetId, ENTITY_TYPE_INTRUSION_SET);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_INTRUSION_SET], args);
};

export const addIntrusionSet = async (context, user, intrusionSet) => {
  const intrusionSetToCreate = pipe(
    assoc('first_seen', isNil(intrusionSet.first_seen) ? new Date(FROM_START) : intrusionSet.first_seen),
    assoc('last_seen', isNil(intrusionSet.last_seen) ? new Date(UNTIL_END) : intrusionSet.last_seen)
  )(intrusionSet);
  const created = await createEntity(context, user, intrusionSetToCreate, ENTITY_TYPE_INTRUSION_SET);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const locationsPaginated = async (context, user, intrusionSetId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, intrusionSetId, RELATION_ORIGINATES_FROM, ENTITY_TYPE_LOCATION, false, args);
};

export const intelligence = async (context, user, intrusionSetId) => {
  if (aiResponseCache[intrusionSetId] && utcDate(aiResponseCache[intrusionSetId].updatedAt).isAfter(minutesAgo(60))) {
    return aiResponseCache[intrusionSetId];
  }
  const intrusionSet = await storeLoadById(context, user, intrusionSetId, ENTITY_TYPE_INTRUSION_SET);
  const indicatorsStats = await getIndicatorsStats(context, user, intrusionSetId, monthsAgo(24), now());
  const victimologyStats = await getVictimologyStats(context, user, intrusionSetId, monthsAgo(24), now());
  const topSectors = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topSectors[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopVictims(context, user, intrusionSetId, ['Sector'], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }
  const topCountries = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topCountries[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopVictims(context, user, intrusionSetId, ['Country'], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }
  const topRegions = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topRegions[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopVictims(context, user, intrusionSetId, ['Region'], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }

  const userPrompt = `
  # Instructions

  - You have to compute a summary of approximately 1000 words based on the following statistics / trends about an intrusion set.
  - The summary should be about the latest activities of the intrusion set.
  - The summary should be formatted in HTML and highlight important numbers with appropriate colors.
  - The used highlight color should be compatible with both light theme and dark themes.
  
  # Interpretation of the data
  - Increasing of indicators of compromise is indicating a surge in the intrusion set activity, which is BAD (red).
  - Decreasing of indicators of compromise is indicating a reduction in the intrusion set activity, which is GOOD (green).
  - Increasing of victims is indicating a surge in the intrusion set activity, which is BAD (red).
  - Decreasing of victims of compromise is indicating a reduction in the intrusion set activity, which is GOOD (green).
  
  # Context
  
  - The summary is about the intrusion set ${intrusionSet.name} (${(intrusionSet.aliases ?? []).join(', ')}). 
  - The description of the intrusion set ${intrusionSet.name} is ${intrusionSet.description}.
  
  # Data
  
  ## Last indicators of compromise (IOCs) statistics.
  This is the number of indicators related to this intrusion sets over time:
  ${JSON.stringify(indicatorsStats)}
  
  ## Last victims statistics
  This is the number of times this intrusion set has targeted something, whether it is an organization, a sector, a location, etc.:
  ${JSON.stringify(victimologyStats)}
  
  ## Top targeted sectors over time
  This is the top sectors targeted over time:
  ${JSON.stringify(topSectors)}
  
  ## Top targeted countries over time
  This is the top countries targeted over time:
  ${JSON.stringify(topCountries)}
  
  ## Top targeted regions over time
  This is the top regions targeted over time:
  ${JSON.stringify(topRegions)}
  `;

  const trends = await queryAi(null, systemPrompt, userPrompt, user);
  const intel = { trends, forecast: trends, updatedAt: utcDate() };
  aiResponseCache[intrusionSetId] = intel;
  return intel;
};
