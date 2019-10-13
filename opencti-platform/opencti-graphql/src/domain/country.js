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
  graknNow,
  takeWriteTx,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'country', args));

export const findById = countryId => getById(countryId);

export const addCountry = async (user, country) => {
  const wTx = await takeWriteTx();
  const internalId = country.internal_id
    ? escapeString(country.internal_id)
    : uuid();
  const now = graknNow();
  const countryIterator = await wTx.tx.query(`insert $country isa Country,
    has internal_id "${internalId}",
    has entity_type "country",
    has stix_id "${
      country.stix_id ? escapeString(country.stix_id) : `identity--${uuid()}`
    }",
    has stix_label "",
    has alias "",
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

  if (country.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdCountryId};
      $to has internal_id "${escapeString(country.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (country.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdCountryId};
         $to has internal_id "${escapeString(markingDefinition)}"; 
         insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      country.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
