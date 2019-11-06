import { assoc, head, join, map, tail } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  escapeString,
  executeWrite,
  loadEntityById,
  graknNow,
  monthFormat,
  paginate,
  prepareDate,
  timeSeries,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { elPaginate } from '../database/elasticSearch';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';
import { notify } from '../database/redis';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'campaign', args));

export const campaignsTimeSeries = args =>
  timeSeries('match $x isa Campaign', args);

export const findByEntity = args =>
  paginate(
    `match $c isa Campaign; 
    $rel($c, $to) isa stix_relation; 
    $to has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );

export const campaignsTimeSeriesByEntity = args =>
  timeSeries(
    `match $x isa Campaign;
     $rel($x, $to) isa stix_relation;
     $to has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );

export const findById = campaignId => loadEntityById(campaignId);

export const addCampaign = async (user, campaign) => {
  const campaignId = await executeWrite(async wTx => {
    const internalId = campaign.internal_id_key
      ? escapeString(campaign.internal_id_key)
      : uuid();
    const now = graknNow();
    const query = `insert $campaign isa Campaign,
    has internal_id_key "${internalId}",
    has entity_type "campaign",
    has stix_id_key "${
      campaign.stix_id_key
        ? escapeString(campaign.stix_id_key)
        : `campaign--${uuid()}`
    }",
    has stix_label "",
    ${
      campaign.alias
        ? `${join(
            ' ',
            map(
              val => `has alias "${escapeString(val)}",`,
              tail(campaign.alias)
            )
          )} has alias "${escapeString(head(campaign.alias))}",`
        : 'has alias "",'
    }
    has name "${escapeString(campaign.name)}",
    has description "${escapeString(campaign.description)}",
    has objective "${escapeString(campaign.objective)}",
    has first_seen ${
      campaign.first_seen ? prepareDate(campaign.first_seen) : now
    },
    has first_seen_day "${
      campaign.first_seen ? dayFormat(campaign.first_seen) : dayFormat(now)
    }",
    has first_seen_month "${
      campaign.first_seen ? monthFormat(campaign.first_seen) : monthFormat(now)
    }",
    has first_seen_year "${
      campaign.first_seen ? yearFormat(campaign.first_seen) : yearFormat(now)
    }",
    has last_seen ${campaign.last_seen ? prepareDate(campaign.last_seen) : now},
    has last_seen_day "${
      campaign.last_seen ? dayFormat(campaign.last_seen) : dayFormat(now)
    }",
    has last_seen_month "${
      campaign.last_seen ? monthFormat(campaign.last_seen) : monthFormat(now)
    }",
    has last_seen_year "${
      campaign.last_seen ? yearFormat(campaign.last_seen) : yearFormat(now)
    }",
    has created ${campaign.created ? prepareDate(campaign.created) : now},
    has modified ${campaign.modified ? prepareDate(campaign.modified) : now},
    has revoked false,
    has created_at ${now},
    has created_at_day "${dayFormat(now)}",
    has created_at_month "${monthFormat(now)}",
    has created_at_year "${yearFormat(now)}",
    has updated_at ${now};
  `;
    logger.debug(`[GRAKN - infer: false] addCampaign > ${query}`);
    const campaignIterator = await wTx.tx.query(query);
    const createCampaign = await campaignIterator.next();
    const createdCampaignId = await createCampaign.map().get('campaign').id;

    // Create associated relations
    await linkCreatedByRef(wTx, createdCampaignId, campaign.createdByRef);
    await linkMarkingDef(wTx, createdCampaignId, campaign.markingDefinitions);
    return internalId;
  });
  return loadEntityById(campaignId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
