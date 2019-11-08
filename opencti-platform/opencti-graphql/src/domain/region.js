import { assoc, head, join, map, tail } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  escapeString,
  executeWrite,
  graknNow,
  loadEntityById,
  monthFormat,
  prepareDate,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elLoadById, elPaginate } from '../database/elasticSearch';
import { addCreatedByRef, addMarkingDefs } from './stixEntity';
import { notify } from '../database/redis';

export const findById = regionId => {
  return elLoadById(regionId);
};
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'region', args));
};

export const addRegion = async (user, region) => {
  const internalId = region.internal_id_key ? escapeString(region.internal_id_key) : uuid();
  await executeWrite(async wTx => {
    const regionIterator = await wTx.tx.query(`insert $region isa Region,
    has internal_id_key "${internalId}",
    has entity_type "region",
    has stix_id_key "${region.stix_id_key ? escapeString(region.stix_id_key) : `identity--${uuid()}`}",
    has stix_label "",
    ${
      region.alias
        ? `${join(' ', map(val => `has alias "${escapeString(val)}",`, tail(region.alias)))} has alias "${escapeString(
            head(region.alias)
          )}",`
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
    return createRegion.map().get('region').id;
  });
  const created = await loadEntityById(internalId);
  await addCreatedByRef(internalId, region.createdByRef);
  await addMarkingDefs(internalId, region.markingDefinitions);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
