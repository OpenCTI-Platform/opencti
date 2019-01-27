import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteByID,
  loadByID,
  notify,
  now,
  paginate,
  takeTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa City', args);

export const findById = cityId => loadByID(cityId);

export const addCity = async (user, city) => {
  const wTx = await takeTx();
  const cityIterator = await wTx.query(`insert $city isa City 
    has type "city";
    $city has stix_id "city--${uuid()}";
    $city has stix_label "";
    $city has stix_label_lowercase "";
    $city has name "${city.name}";
    $city has description "${city.description}";
    $city has name_lowercase "${city.name.toLowerCase()}";
    $city has description_lowercase "${
      city.description ? city.description.toLowerCase() : ''
    }";
    $city has created ${now()};
    $city has modified ${now()};
    $city has revoked false;
    $city has created_at ${now()};
    $city has updated_at ${now()};
  `);
  const createCity = await cityIterator.next();
  const createdCityId = await createCity.map().get('city').id;

  if (city.createdByRef) {
    await wTx.query(`match $from id ${createdCityId};
         $to id ${city.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (city.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdCityId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      city.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return loadByID(createdCityId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const cityDelete = cityId => deleteByID(cityId);
