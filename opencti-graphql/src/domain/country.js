import { head } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteByID,
  loadByID,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  qk,
  prepareString
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Country', args);

export const findById = countryId => loadByID(countryId);

export const markingDefinitions = (countryId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$country) isa object_marking_refs; 
    $country id ${countryId}`,
    args
  );

export const addCountry = async (user, country) => {
  const createCountry = qk(`insert $country isa Country 
    has type "country";
    $country has stix_id "country--${uuid()}";
    $country has stix_label "";
    $country has stix_label_lowercase "";
    $country has alias "";
    $country has alias_lowercase "";
    $country has name "${prepareString(country.name)}";
    $country has description "${prepareString(country.description)}";
    $country has name_lowercase "${prepareString(country.name.toLowerCase())}";
    $country has description_lowercase "${
      country.description
        ? prepareString(country.description.toLowerCase())
        : ''
    }";
    $country has created ${now()};
    $country has modified ${now()};
    $country has revoked false;
    $country has created_at ${now()};
    $country has created_at_day "${dayFormat(now())}";
    $country has created_at_month "${monthFormat(now())}";
    $country has created_at_year "${yearFormat(now())}";
    $country has updated_at ${now()};
  `);
  return createCountry.then(result => {
    const { data } = result;
    return loadByID(head(data).country.id).then(created =>
      notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
    );
  });
};

export const countryDelete = countryId => deleteByID(countryId);
