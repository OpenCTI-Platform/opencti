import { head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Organization', args);

export const findById = organizationId => loadByID(organizationId);

export const markingDefinitions = (organizationId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$organization) isa object_marking_refs; 
    $organization id ${organizationId}`,
    args
  );

export const addOrganization = async (user, organization) => {
  const createOrganization = qk(`insert $organization isa Organization 
    has type "organization";
    $organization has stix_id "organization--${uuid()}";
    $organization has name "${organization.name}";
    $organization has description "${organization.description}";
    $organization has name_lowercase "${organization.name.toLowerCase()}";
    $organization has description_lowercase "${
      organization.description ? organization.description.toLowerCase() : ''
    }";
    $organization has created ${now()};
    $organization has modified ${now()};
    $organization has revoked false;
    $organization has created_at ${now()};
    $organization has updated_at ${now()};
  `);
  return createOrganization.then(result => {
    const { data } = result;
    return loadByID(head(data).organization.id).then(created =>
      notify(BUS_TOPICS.Organization.ADDED_TOPIC, created, user)
    );
  });
};

export const organizationDelete = organizationId => deleteByID(organizationId);

export const organizationAddRelation = (user, organizationId, input) =>
  createRelation(organizationId, input).then(relationData => {
    notify(BUS_TOPICS.Organization.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const organizationDeleteRelation = (user, organizationId, relationId) =>
  deleteRelation(organizationId, relationId).then(relationData => {
    notify(BUS_TOPICS.Organization.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const organizationCleanContext = (user, organizationId) => {
  delEditContext(user, organizationId);
  return loadByID(organizationId).then(organization =>
    notify(BUS_TOPICS.Organization.EDIT_TOPIC, organization, user)
  );
};

export const organizationEditContext = (user, organizationId, input) => {
  setEditContext(user, organizationId, input);
  return loadByID(organizationId).then(organization =>
    notify(BUS_TOPICS.Organization.EDIT_TOPIC, organization, user)
  );
};

export const organizationEditField = (user, organizationId, input) =>
  editInputTx(organizationId, input).then(organization =>
    notify(BUS_TOPICS.Organization.EDIT_TOPIC, organization, user)
  );
