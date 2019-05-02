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
  elPaginate('stix-domain-entities', assoc('type', 'city', args));
// paginate('match $c isa City', args);

export const findById = cityId => getById(cityId);

export const addCity = async (user, city) => {
  const wTx = await takeWriteTx();
  const cityIterator = await wTx.query(`insert $city isa City,
    has entity_type "city",
    has stix_id "${
      city.stix_id ? escapeString(city.stix_id) : `city--${uuid()}`
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
    await wTx.query(
      `match $from id ${createdCityId};
      $to id ${escape(city.createdByRef)};
      insert (so: $from, creator: $to)
      isa created_by_ref;`
    );
  }

  if (city.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdCityId}; 
        $to id ${escape(markingDefinition)}; 
        insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      city.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdCityId).then(created => {
    index('stix-domain-entities', 'stix_domain_entity', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
