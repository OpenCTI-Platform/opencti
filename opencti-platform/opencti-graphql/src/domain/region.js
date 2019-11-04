import { assoc, head, join, map, tail } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  escapeString,
  executeWrite,
  refetchEntityById,
  graknNow,
  monthFormat,
  notify,
  prepareDate,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'region', args));

export const findById = regionId => refetchEntityById(regionId);

export const addRegion = async (user, region) => {
  const regionId = await executeWrite(async wTx => {
    const internalId = region.internal_id_key
      ? escapeString(region.internal_id_key)
      : uuid();
    const regionIterator = await wTx.tx.query(`insert $region isa Region,
    has internal_id_key "${internalId}",
    has entity_type "region",
    has stix_id_key "${
      region.stix_id_key
        ? escapeString(region.stix_id_key)
        : `identity--${uuid()}`
    }",
    has stix_label "",
    ${
      region.alias
        ? `${join(
            ' ',
            map(val => `has alias "${escapeString(val)}",`, tail(region.alias))
          )} has alias "${escapeString(head(region.alias))}",`
        : 'has alias "",'
    }
    has name "${escapeString(region.name)}",
    has description "${escapeString(region.description)}",
    has created ${region.created ? prepareDate(region.created) : graknNow()},
    has modified ${region.modified ? prepareDate(region.modified) : graknNow()},
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",
    has updated_at ${graknNow()};
  `);
    const createRegion = await regionIterator.next();
    const createdRegionId = await createRegion.map().get('region').id;

    // Create associated relations
    await linkCreatedByRef(wTx, createdRegionId, region.createdByRef);
    await linkMarkingDef(wTx, createdRegionId, region.markingDefinitions);
    return internalId;
  });
  return refetchEntityById(regionId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
