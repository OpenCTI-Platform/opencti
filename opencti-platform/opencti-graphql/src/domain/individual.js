import * as R from 'ramda';
import { createEntity } from '../database/middleware';
import { listEntities, listEntitiesThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_PART_OF } from '../schema/stixCoreRelationship';
import { SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { isEmptyField } from '../database/utils';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';

export const findById = (context, user, individualId) => {
  return storeLoadById(context, user, individualId, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_IDENTITY_INDIVIDUAL], args);
};

export const addIndividual = async (context, user, individual, opts = {}) => {
  const inputWithClass = R.assoc('identity_class', ENTITY_TYPE_IDENTITY_INDIVIDUAL.toLowerCase(), individual);
  const created = await createEntity(context, user, inputWithClass, ENTITY_TYPE_IDENTITY_INDIVIDUAL, opts);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const partOfOrganizationsPaginated = async (context, user, individualId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, individualId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION, false, false, args);
};

export const isUser = async (context, individualContactInformation) => {
  if (isEmptyField(individualContactInformation)) {
    return false;
  }
  const args = {
    filters: {
      mode: 'and',
      filters: [{ key: 'user_email', values: [individualContactInformation] }],
      filterGroups: [],
    },
    connectionFormat: false
  };
  const users = await listEntities(context, SYSTEM_USER, [ENTITY_TYPE_USER], args);
  return users.length > 0;
};
