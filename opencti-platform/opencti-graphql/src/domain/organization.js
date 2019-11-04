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
import { linkCreatedByRef, linkMarkingDef, linkTags } from './stixEntity';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'organization', args));

export const findById = organizationId => getById(organizationId);

export const addOrganization = async (user, organization) => {
  const orgaId = await executeWrite(async wTx => {
    const internalId = organization.internal_id_key
      ? escapeString(organization.internal_id_key)
      : uuid();
    const organizationIterator = await wTx.tx
      .query(`insert $organization isa Organization,
    has internal_id_key "${internalId}",
    has entity_type "organization",
    has stix_id_key "${
      organization.stix_id_key
        ? escapeString(organization.stix_id_key)
        : `identity--${uuid()}`
    }",
    has stix_label "",
    ${
      organization.alias
        ? `${join(
            ' ',
            map(
              val => `has alias "${escapeString(val)}",`,
              tail(organization.alias)
            )
          )} has alias "${escapeString(head(organization.alias))}",`
        : 'has alias "",'
    }
    has name "${escapeString(organization.name)}",
    has description "${escapeString(organization.description)}",
    has organization_class "${
      organization.organization_class
        ? escapeString(organization.organization_class)
        : 'other'
    }",
    has created ${
      organization.created ? prepareDate(organization.created) : graknNow()
    },
    has modified ${
      organization.modified ? prepareDate(organization.modified) : graknNow()
    },
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",         
    has updated_at ${graknNow()};
  `);
    const createOrga = await organizationIterator.next();
    const createdId = await createOrga.map().get('organization').id;
    // Create associated relations
    await linkCreatedByRef(wTx, createdId, organization.createdByRef);
    await linkMarkingDef(wTx, createdId, organization.markingDefinitions);
    await linkTags(wTx, createdId, organization.tags);
    return internalId;
  });
  return getById(orgaId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
