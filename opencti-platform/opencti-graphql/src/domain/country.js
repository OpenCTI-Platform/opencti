import { assoc, head, join, map, tail } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  escapeString,
  executeWrite,
  loadEntityById,
  graknNow,
  monthFormat,
  prepareDate,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elPaginate } from '../database/elasticSearch';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';
import { notify } from '../database/redis';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'country', args));

export const findById = countryId => loadEntityById(countryId);

export const addCountry = async (user, country) => {
  const countryId = await executeWrite(async wTx => {
    const internalId = country.internal_id_key
      ? escapeString(country.internal_id_key)
      : uuid();
    const now = graknNow();
    const countryIterator = await wTx.tx.query(`insert $country isa Country,
    has internal_id_key "${internalId}",
    has entity_type "country",
    has stix_id_key "${
      country.stix_id_key
        ? escapeString(country.stix_id_key)
        : `identity--${uuid()}`
    }",
    has stix_label "",
    ${
      country.alias
        ? `${join(
            ' ',
            map(val => `has alias "${escapeString(val)}",`, tail(country.alias))
          )} has alias "${escapeString(head(country.alias))}",`
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
    const createdCountryId = await createCountry.map().get('country').id;

    // Create associated relations
    await linkCreatedByRef(wTx, createdCountryId, country.createdByRef);
    await linkMarkingDef(wTx, createdCountryId, country.markingDefinitions);
    return internalId;
  });
  return loadEntityById(countryId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
