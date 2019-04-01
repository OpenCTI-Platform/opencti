import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteEntityById,
  getById,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  prepareString,
  takeWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $c isa Country', args);

export const findById = countryId => getById(countryId);

export const addCountry = async (user, country) => {
  const wTx = await takeWriteTx();
  const countryIterator = await wTx.query(`insert $country isa Country,
    has entity_type "country",
    has stix_id "${
      country.stix_id ? prepareString(country.stix_id) : `country--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${prepareString(country.name)}",
    has description "${prepareString(country.description)}",
    has created ${country.created ? prepareDate(country.created) : now()},
    has modified ${country.modified ? prepareDate(country.modified) : now()},
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",
    has updated_at ${now()};
  `);
  const createCountry = await countryIterator.next();
  const createdCountryId = await createCountry.map().get('country').id;

  if (country.createdByRef) {
    await wTx.query(
      `match $from id ${createdCountryId};
      $to id ${country.createdByRef};
      insert (so: $from, creator: $to)
      isa created_by_ref;`
    );
  }

  if (country.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdCountryId};
         $to id ${markingDefinition}; 
         insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      country.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdCountryId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const countryDelete = countryId => deleteEntityById(countryId);
