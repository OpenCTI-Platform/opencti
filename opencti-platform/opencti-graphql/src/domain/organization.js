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
import { index, paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'organization', args));

export const findById = organizationId => getById(organizationId);

export const addOrganization = async (user, organization) => {
  const wTx = await takeWriteTx();
  const internalId = organization.internal_id
    ? escapeString(organization.internal_id)
    : uuid();
  const organizationIterator = await wTx.tx
    .query(`insert $organization isa Organization,
    has internal_id "${internalId}",
    has entity_type "organization",
    has stix_id "${
      organization.stix_id
        ? escapeString(organization.stix_id)
        : `identity--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(organization.name)}",
    has description "${escapeString(organization.description)}",
    has organization_class "${
      organization.organization_class
        ? escapeString(organization.organization_class)
        : 'other'
    }",
    has created ${
      organization.created ? prepareDate(organization.created) : now()
    },
    has modified ${
      organization.modified ? prepareDate(organization.modified) : now()
    },
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",         
    has updated_at ${now()};
  `);
  const createOrganization = await organizationIterator.next();
  const createdOrganizationId = await createOrganization
    .map()
    .get('organization').id;

  if (organization.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdOrganizationId};
      $to has internal_id "${escapeString(organization.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (organization.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdOrganizationId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      organization.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    index('stix_domain_entities', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
