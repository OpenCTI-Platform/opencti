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
  takeWriteTx,
  prepareString
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Organization', args);

export const findById = organizationId => getById(organizationId);

export const addOrganization = async (user, organization) => {
  const wTx = await takeWriteTx();
  const organizationIterator = await wTx.query(`insert $organization isa Organization 
    has type "organization";
    $organization has stix_id "organization--${uuid()}";
    $organization has stix_label "";
    $organization has alias "";
    $organization has name "${prepareString(organization.name)}";
    $organization has description "${prepareString(organization.description)}";
    $organization has created ${now()};
    $organization has modified ${now()};
    $organization has revoked false;
    $organization has created_at ${now()};
    $organization has created_at_day "${dayFormat(now())}";
    $organization has created_at_month "${monthFormat(now())}";
    $organization has created_at_year "${yearFormat(now())}";         
    $organization has updated_at ${now()};
  `);
  const createOrganization = await organizationIterator.next();
  const createdOrganizationId = await createOrganization
    .map()
    .get('organization').id;

  if (organization.createdByRef) {
    await wTx.query(`match $from id ${createdOrganizationId};
         $to id ${organization.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (organization.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdOrganizationId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      organization.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdOrganizationId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const organizationDelete = organizationId => deleteEntityById(organizationId);
