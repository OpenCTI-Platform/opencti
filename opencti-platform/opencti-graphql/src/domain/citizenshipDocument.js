import * as R from 'ramda';
import { createEntity } from '../database/middleware';
import { pageEntitiesConnection, pageRegardingEntitiesConnection, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_PART_OF } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { buildPagination } from '../database/utils';
// TODO REVIEW
export const findById = (context, user, citizenshipDocumentId) => {
  return storeLoadById(context, user, citizenshipDocumentId, ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT);
};

export const findCitizenshipDocumentPaginated = (context, user, args) => {
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT], args);
};

export const addCitizenshipDocument = async (context, user, citizenshipDocument, opts = {}) => {
  const inputWithClass = R.assoc('identity_class', ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT.toLowerCase(), citizenshipDocument);
  const created = await createEntity(context, user, inputWithClass, ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT, opts);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const partOfOrganizationsPaginated = async (context, user, citizenshipDocumentId, args) => {
  const checkIndividualAccess = await findById(context, user, citizenshipDocumentId);
  if (!checkIndividualAccess) {
    return buildPagination(0, null, [], 0);
  }
  return pageRegardingEntitiesConnection(context, user, citizenshipDocumentId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION, false, args);
};
