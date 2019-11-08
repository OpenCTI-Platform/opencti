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

export const findById = countryId => {
  return elLoadById(countryId);
};
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'country', args));
};

export const addCountry = async (user, country) => {
  const internalId = country.internal_id_key ? escapeString(country.internal_id_key) : uuid();
  await executeWrite(async wTx => {
    const now = graknNow();
    const countryIterator = await wTx.tx.query(`insert $country isa Country,
    has internal_id_key "${internalId}",
    has entity_type "country",
    has stix_id_key "${country.stix_id_key ? escapeString(country.stix_id_key) : `identity--${uuid()}`}",
    has stix_label "",
    ${
      country.alias
        ? `${join(' ', map(val => `has alias "${escapeString(val)}",`, tail(country.alias)))} has alias "${escapeString(
            head(country.alias)
          )}",`
        : 'has alias "",'
    }
    has name "${escapeString(country.name)}",
    has description "${escapeString(country.description)}",
    has created ${country.created ? prepareDate(country.created) : now},
    has modified ${country.modified ? prepareDate(country.modified) : now},
    has revoked false,
    has created_at ${now},
    has created_at_day "${dayFormat(now)}",
    has created_at_month "${monthFormat(now)}",
    has created_at_year "${yearFormat(now)}",
    has updated_at ${now};
  `);
    const createCountry = await countryIterator.next();
    return createCountry.map().get('country').id;
  });
  const created = await loadEntityById(internalId);
  await addCreatedByRef(internalId, country.createdByRef);
  await addMarkingDefs(internalId, country.markingDefinitions);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
