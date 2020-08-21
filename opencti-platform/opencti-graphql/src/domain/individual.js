import { assoc } from 'ramda';
import { createEntity, listEntities, listToEntitiesThroughRelation, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import {
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  RELATION_PART_OF,
} from '../utils/idGenerator';

export const findById = (individualId) => {
  return loadEntityById(individualId, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_IDENTITY_INDIVIDUAL], ['name', 'description', 'x_opencti_aliases'], args);
};

export const addIndividual = async (user, individual) => {
  const created = await createEntity(
    user,
    assoc('identity_class', ENTITY_TYPE_IDENTITY_INDIVIDUAL.toLowerCase(), individual),
    ENTITY_TYPE_IDENTITY_INDIVIDUAL
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const organizations = (individualId) => {
  return listToEntitiesThroughRelation(individualId, null, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION);
};
