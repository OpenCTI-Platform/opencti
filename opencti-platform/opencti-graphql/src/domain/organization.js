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
import { elPaginate } from '../database/elasticSearch';
import { addCreatedByRef, addMarkingDefs } from './stixEntity';
import { notify } from '../database/redis';

export const findById = organizationId => {
  return loadEntityById(organizationId);
};
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'organization', args));
};

export const addOrganization = async (user, organization) => {
  const internalId = organization.internal_id_key ? escapeString(organization.internal_id_key) : uuid();
  await executeWrite(async wTx => {
    const organizationIterator = await wTx.tx.query(`insert $organization isa Organization,
    has internal_id_key "${internalId}",
    has entity_type "organization",
    has stix_id_key "${organization.stix_id_key ? escapeString(organization.stix_id_key) : `identity--${uuid()}`}",
    has stix_label "",
    ${
      organization.alias
        ? `${join(
            ' ',
            map(val => `has alias "${escapeString(val)}",`, tail(organization.alias))
          )} has alias "${escapeString(head(organization.alias))}",`
        : 'has alias "",'
    }
    has name "${escapeString(organization.name)}",
    has description "${escapeString(organization.description)}",
    has organization_class "${
      organization.organization_class ? escapeString(organization.organization_class) : 'other'
    }",
    has created ${organization.created ? prepareDate(organization.created) : graknNow()},
    has modified ${organization.modified ? prepareDate(organization.modified) : graknNow()},
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",         
    has updated_at ${graknNow()};
  `);
    const createOrga = await organizationIterator.next();
    return createOrga.map().get('organization').id;
  });
  const created = await loadEntityById(internalId);
  await addCreatedByRef(internalId, organization.createdByRef);
  await addMarkingDefs(internalId, organization.markingDefinitions);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
