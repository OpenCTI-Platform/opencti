import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  escapeString,
  getById,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  prepareDate,
  takeWriteTx,
  timeSeries,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { index, paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate('stix-domain-entities', assoc('type', 'campaign', args));
// paginate('match $m isa Campaign', args);

export const search = args =>
  elPaginate('stix-domain-entities', assoc('type', 'campaign', args));
/*
  paginate(
    `match $c isa Campaign; 
    $c has name $name; 
    $c has alias $alias;
    { $name contains "${escapeString(args.search)}"; } or
    { $alias contains "${escapeString(args.search)}"; }`,
    args,
    false
  );
*/

export const campaignsTimeSeries = args =>
  timeSeries('match $x isa Campaign', args);

export const findByEntity = args =>
  paginate(
    `match $c isa Campaign; 
    $rel($c, $to) isa stix_relation; 
    $to has internal_id "${escapeString(args.objectId)}"`,
    args
  );

export const campaignsTimeSeriesByEntity = args =>
  timeSeries(
    `match $x isa Campaign;
     $rel($x, $to) isa stix_relation;
     $to has internal_id "${escapeString(args.objectId)}"`,
    args
  );

export const findById = campaignId => getById(campaignId);

export const addCampaign = async (user, campaign) => {
  const wTx = await takeWriteTx();
  const internalId = campaign.internal_id
    ? escapeString(campaign.internal_id)
    : uuid();
  const query = `insert $campaign isa Campaign,
    has internal_id "${internalId}",
    has entity_type "campaign",
    has stix_id "${
      campaign.stix_id ? escapeString(campaign.stix_id) : `campaign--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(campaign.name)}",
    has description "${escapeString(campaign.description)}",
    has objective "${escapeString(campaign.objective)}",
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
  const campaignIterator = await wTx.tx.query(query);
  const createCampaign = await campaignIterator.next();
  const createdCampaignId = await createCampaign.map().get('campaign').id;

  if (campaign.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdCampaignId};
      $to has internal_id "${escapeString(campaign.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (campaign.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdCampaignId};
        $to has internal_id "${escapeString(markingDefinition)}";
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      campaign.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    index('stix-domain-entities', 'stix_domain_entity', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
