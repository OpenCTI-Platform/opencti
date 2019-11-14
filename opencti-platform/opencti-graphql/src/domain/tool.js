import { assoc } from 'ramda';
import { createEntity, loadEntityById, TYPE_STIX_DOMAIN_ENTITY } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elPaginate } from '../database/elasticSearch';
import { notify } from '../database/redis';

export const findById = toolId => loadEntityById(toolId);
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'tool', args));
};

export const addTool = async (user, tool) => {
  const created = await createEntity(tool, 'Tool', TYPE_STIX_DOMAIN_ENTITY);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
