import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  escapeString,
  getById,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  takeWriteTx,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'city', args));

export const findById = cityId => getById(cityId);

export const addCity = async (user, city) => {
  const wTx = await takeWriteTx();
  const internalId = city.internal_id_key ? escapeString(city.internal_id_key) : uuid();
  const cityIterator = await wTx.tx.query(`insert $city isa City,
    has internal_id_key "${internalId}",
    has entity_type "city",
    has stix_id_key "${
      city.stix_id_key ? escapeString(city.stix_id_key) : `identity--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(city.name)}",
    has description "${escapeString(city.description)}",
    has created ${city.created ? prepareDate(city.created) : now()},
    has modified ${city.modified ? prepareDate(city.modified) : now()},
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",
    has updated_at ${now()};
  `);
  const createCity = await cityIterator.next();
  const createdCityId = await createCity.map().get('city').id;

  if (city.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdCityId};
      $to has internal_id_key "${escapeString(city.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id_key "${uuid()}";`
    );
  }

  if (city.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdCityId}; 
        $to has internal_id_key "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id_key "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      city.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
