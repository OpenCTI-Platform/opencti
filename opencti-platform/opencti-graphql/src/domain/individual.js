import { assoc } from 'ramda';
import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../utils/idGenerator';

export const findById = (individualId) => {
  return loadEntityById(individualId, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_IDENTITY_INDIVIDUAL], ['name', 'description', 'aliases'], args);
};

export const addIndividual = async (user, individual) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_identity_type', ENTITY_TYPE_IDENTITY_INDIVIDUAL, individual),
    ENTITY_TYPE_IDENTITY_INDIVIDUAL
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
