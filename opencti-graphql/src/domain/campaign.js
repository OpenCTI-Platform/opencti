import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteEntityById,
  getById,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  prepareDate,
  takeWriteTx,
  prepareString,
  timeSeries
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';

export const findAll = args => paginate('match $m isa Campaign', args);

export const search = args =>
  paginate(
    `match $c isa Campaign; 
    $c has name $name; 
    $c has alias $alias;
    { $name contains "${prepareString(args.search)}"; } or
    { $alias contains "${prepareString(args.search)}"; }`,
    args,
    false
  );

export const campaignsTimeSeries = args =>
  timeSeries('match $c isa Campaign', args);

export const findByEntity = args =>
  paginate(
    `match $c isa Campaign; 
    $rel($c, $to) isa stix_relation; 
    $to id ${args.objectId}`,
    args
  );

export const campaignsTimeSeriesByEntity = args =>
  timeSeries(
    `match $c isa Campaign;
     $rel($c, $to) isa stix_relation;
     $to id ${args.objectId}`,
    args
  );

export const findById = campaignId => getById(campaignId);

export const addCampaign = async (user, campaign) => {
  const wTx = await takeWriteTx();
  const query = `insert $campaign isa Campaign,
    has entity_type "campaign",
    has stix_id "${
      campaign.stix_id ? prepareString(campaign.stix_id) : `campaign--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${prepareString(campaign.name)}",
    has description "${prepareString(campaign.description)}",
    has objective "${prepareString(campaign.objective)}",
    has first_seen ${
      campaign.first_seen ? prepareDate(campaign.first_seen) : now()
    },
    has first_seen_day "${
      campaign.first_seen ? dayFormat(campaign.first_seen) : dayFormat(now())
    }",
    has first_seen_month "${
      campaign.first_seen
        ? monthFormat(campaign.first_seen)
        : monthFormat(now())
    }",
    has first_seen_year "${
      campaign.first_seen ? yearFormat(campaign.first_seen) : yearFormat(now())
    }",
    has last_seen ${
      campaign.last_seen ? prepareDate(campaign.last_seen) : now()
    },
    has last_seen_day "${
      campaign.last_seen ? dayFormat(campaign.last_seen) : dayFormat(now())
    }",
    has last_seen_month "${
      campaign.last_seen ? monthFormat(campaign.last_seen) : monthFormat(now())
    }",
    has last_seen_year "${
      campaign.last_seen ? yearFormat(campaign.last_seen) : yearFormat(now())
    }",
    has created ${campaign.created ? prepareDate(campaign.created) : now()},
    has modified ${campaign.modified ? prepareDate(campaign.modified) : now()},
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",
    has updated_at ${now()};
  `;
  logger.debug(`[GRAKN - infer: false] ${query}`);
  const campaignIterator = await wTx.query(query);
  const createCampaign = await campaignIterator.next();
  const createdCampaignId = await createCampaign.map().get('campaign').id;

  if (campaign.createdByRef) {
    await wTx.query(
      `match $from id ${createdCampaignId};
      $to id ${campaign.createdByRef};
      insert (so: $from, creator: $to)
      isa created_by_ref;`
    );
  }

  if (campaign.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdCampaignId};
        $to id ${markingDefinition};
        insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      campaign.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdCampaignId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const campaignDelete = campaignId => deleteEntityById(campaignId);
