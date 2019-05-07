import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  escape,
  escapeString,
  getById,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  takeWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { index, paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate('stix-domain-entities', assoc('type', 'region', args));
// paginate('match $r isa Region', args);

export const findById = regionId => getById(regionId);

export const addRegion = async (user, region) => {
  const wTx = await takeWriteTx();
  const regionIterator = await wTx.query(`insert $region isa Region,
    has internal_id "${
      region.internal_id ? escapeString(region.internal_id) : uuid()
    }",
    has entity_type "region",
    has stix_id "${
      region.stix_id ? escapeString(region.stix_id) : `region--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(region.name)}",
    has description "${escapeString(region.description)}",
    has created ${region.created ? prepareDate(region.created) : now()},
    has modified ${region.modified ? prepareDate(region.modified) : now()},
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",
    has updated_at ${now()};
  `);
  const createRegion = await regionIterator.next();
  const createdRegionId = await createRegion.map().get('region').id;

  if (region.createdByRef) {
    await wTx.query(
      `match $from id ${createdRegionId};
      $to has internal_id "${escapeString(region.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (region.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdRegionId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      region.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdRegionId).then(created => {
    index('stix-domain-entities', 'stix_domain_entity', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
