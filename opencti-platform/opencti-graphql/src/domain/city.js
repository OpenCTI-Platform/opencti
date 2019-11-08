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

export const findById = cityId => {
  return elLoadById(cityId);
};
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'city', args));
};

export const addCity = async (user, city) => {
  const internalId = city.internal_id_key ? escapeString(city.internal_id_key) : uuid();
  await executeWrite(async wTx => {
    const cityIterator = await wTx.tx.query(`insert $city isa City,
    has internal_id_key "${internalId}",
    has entity_type "city",
    has stix_id_key "${city.stix_id_key ? escapeString(city.stix_id_key) : `identity--${uuid()}`}",
    has stix_label "",
    ${
      city.alias
        ? `${join(' ', map(val => `has alias "${escapeString(val)}",`, tail(city.alias)))} has alias "${escapeString(
            head(city.alias)
          )}",`
        : 'has alias "",'
    }
    has name "${escapeString(city.name)}",
    has description "${escapeString(city.description)}",
    has created ${city.created ? prepareDate(city.created) : graknNow()},
    has modified ${city.modified ? prepareDate(city.modified) : graknNow()},
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",
    has updated_at ${graknNow()};
  `);
    const createCity = await cityIterator.next();
    return createCity.map().get('city').id;
  });
  const createdCity = await loadEntityById(internalId);
  await addCreatedByRef(internalId, city.createdByRef);
  await addMarkingDefs(internalId, city.markingDefinitions);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, createdCity, user);
};
