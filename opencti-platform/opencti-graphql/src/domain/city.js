import { assoc, head, join, map, tail } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  escapeString,
  executeWrite,
  getById,
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
  elPaginate('stix_domain_entities', assoc('type', 'city', args));

export const findById = cityId => getById(cityId);

export const addCity = async (user, city) => {
  const cityId = await executeWrite(async wTx => {
    const internalId = city.internal_id_key
      ? escapeString(city.internal_id_key)
      : uuid();
    const cityIterator = await wTx.tx.query(`insert $city isa City,
    has internal_id_key "${internalId}",
    has entity_type "city",
    has stix_id_key "${
      city.stix_id_key ? escapeString(city.stix_id_key) : `identity--${uuid()}`
    }",
    has stix_label "",
    ${
      city.alias
        ? `${join(
            ' ',
            map(val => `has alias "${escapeString(val)}",`, tail(city.alias))
          )} has alias "${escapeString(head(city.alias))}",`
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
    const createdCityId = await createCity.map().get('city').id;
    // Create associated relations
    await linkCreatedByRef(wTx, createdCityId, city.createdByRef);
    await linkMarkingDef(wTx, createdCityId, city.markingDefinitions);
    return internalId;
  });
  return getById(cityId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
