import { pipe, assoc, dissoc, filter, map, isNil } from "ramda";
import { createEntity, listEntities, loadById, updateAttribute } from "../database/grakn";
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
  return listEntities(types, ['name', 'description', 'x_opencti_aliases'], args);
};

export const addIdentity = async (user, identity) => {
  let identityClass = identity.type.toLowerCase();
  if (identityClass === 'sector') {
    identityClass = 'class';
  }
  const identityToCreate = pipe(assoc('identity_class', identityClass), dissoc('type'))(identity);
  const created = await createEntity(user, identityToCreate, identity.type);
  if (identity.update === true) {
    const fieldsToUpdate = ['description'];
    await Promise.all(
      map((field) => {
        if (!isNil(identity[field])) {
          return updateAttribute(user, created.id, created.entity_type, { key: field, value: [identity[field]] });
        }
        return true;
      }, fieldsToUpdate)
    );
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
