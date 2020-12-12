import { pipe, assoc, dissoc, filter } from 'ramda';
import { createEntity, listEntities, loadById } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_IDENTITY } from '../schema/general';
import { isStixDomainObjectIdentity } from '../schema/stixDomainObject';

export const findById = async (identityId) => {
  return loadById(identityId, ENTITY_TYPE_IDENTITY);
};

export const findAll = async (args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixDomainObjectIdentity(type), args.types);
  }
  if (types.length === 0) {
    types.push(ENTITY_TYPE_IDENTITY);
  }
  return listEntities(types, args);
};

export const addIdentity = async (user, identity) => {
  let identityClass = identity.type.toLowerCase();
  if (identityClass === 'sector') {
    identityClass = 'class';
  }
  const identityToCreate = pipe(assoc('identity_class', identityClass), dissoc('type'))(identity);
  const created = await createEntity(user, identityToCreate, identity.type);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
