import { pipe, assoc, dissoc, filter } from 'ramda';
import { createEntity } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_IDENTITY } from '../schema/general';
import { ENTITY_TYPE_IDENTITY_SECTOR, isStixDomainObjectIdentity } from '../schema/stixDomainObject';
import { listEntities, storeLoadById } from '../database/middleware-loader';

export const findById = async (context, user, identityId) => {
  return storeLoadById(context, user, identityId, ENTITY_TYPE_IDENTITY);
};

export const findAll = async (context, user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixDomainObjectIdentity(type), args.types);
  }
  if (types.length === 0) {
    types.push(ENTITY_TYPE_IDENTITY);
  }
  return listEntities(context, user, types, args);
};

export const addIdentity = async (context, user, identity) => {
  const identityClass = identity.type === ENTITY_TYPE_IDENTITY_SECTOR ? 'class' : identity.type.toLowerCase();
  const identityToCreate = pipe(assoc('identity_class', identityClass), dissoc('type'))(identity);
  const created = await createEntity(context, user, identityToCreate, identity.type);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
