import * as R from 'ramda';
import { createEntity, batchListThroughGetTo } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_PART_OF } from '../schema/stixCoreRelationship';
import { SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { isEmptyField } from '../database/utils';

export const findById = (context, user, individualId) => {
  return storeLoadById(context, user, individualId, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_IDENTITY_INDIVIDUAL], args);
};

export const addIndividual = async (context, user, individual) => {
  const created = await createEntity(
    context,
    user,
    R.assoc('identity_class', ENTITY_TYPE_IDENTITY_INDIVIDUAL.toLowerCase(), individual),
    ENTITY_TYPE_IDENTITY_INDIVIDUAL
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchOrganizations = (context, user, individualIds) => {
  return batchListThroughGetTo(context, user, individualIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION);
};

export const isUser = async (context, user, individualContactInformation) => {
  if (isEmptyField(individualContactInformation)) {
    return false;
  }
  const args = { filters: [{ key: 'user_email', values: [individualContactInformation] }], connectionFormat: false };
  const users = await listEntities(context, SYSTEM_USER, [ENTITY_TYPE_USER], args);
  return users.length > 0;
};
