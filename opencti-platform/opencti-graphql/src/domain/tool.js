import { assoc } from 'ramda';
import { createEntity, listEntities, loadEntityById, TYPE_STIX_DOMAIN_ENTITY } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = toolId => loadEntityById(toolId);
export const findAll = args => {
  const typedArgs = assoc('types', ['Tool'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

export const addTool = async (user, tool) => {
  const created = await createEntity(tool, 'Tool', TYPE_STIX_DOMAIN_ENTITY);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
