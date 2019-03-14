import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteEntityById,
  getById,
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

export const findAll = args => paginate('match $m isa Country', args);

export const findById = countryId => getById(countryId);

export const markingDefinitions = (countryId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$country) isa object_marking_refs; 
    $country id ${countryId}`,
    args
  );

export const addCountry = async (user, country) => {
  const wTx = await takeWriteTx();
  const countryIterator = await wTx.query(`insert $country isa Country 
    has type "country";
    $country has stix_id "country--${uuid()}";
    $country has stix_label "";
    $country has alias "";
    $country has name "${prepareString(country.name)}";
    $country has description "${prepareString(country.description)}";
    $country has created ${now()};
    $country has modified ${now()};
    $country has revoked false;
    $country has created_at ${now()};
    $country has created_at_day "${dayFormat(now())}";
    $country has created_at_month "${monthFormat(now())}";
    $country has created_at_year "${yearFormat(now())}";
    $country has updated_at ${now()};
  `);
  const createCountry = await countryIterator.next();
  const createdCountryId = await createCountry.map().get('country').id;

  if (country.createdByRef) {
    await wTx.query(`match $from id ${createdCountryId};
         $to id ${country.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (country.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdCountryId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
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
