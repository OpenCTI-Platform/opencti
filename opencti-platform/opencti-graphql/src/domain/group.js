import { assoc, concat } from 'ramda';
import { createEntity, deleteEntityById, listEntities, loadEntityById, TYPE_OPENCTI_INTERNAL } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { findAll as findAllUsers } from './user';
import { findAll as findAllMarkings } from './markingDefinition';

// region grakn fetch
export const findById = groupId => {
  return loadEntityById(groupId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Group'], args);
  return listEntities(['name'], typedArgs);
};
export const members = async (groupId, args) => {
  const filters = concat([{ key: 'membership.internal_id_key', values: [groupId] }], args.filters || []);
  const filterArgs = assoc('filters', filters, args);
  return findAllUsers(filterArgs);
};
export const permissions = async (groupId, args) => {
  const filters = concat([{ key: 'permission.internal_id_key', values: [groupId] }], args.filters || []);
  const filterArgs = assoc('filters', filters, args);
  return findAllMarkings(filterArgs);
};
// endregion

export const addGroup = async (user, group) => {
  const created = await createEntity(group, 'Group', TYPE_OPENCTI_INTERNAL);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};

export const groupDelete = groupId => deleteEntityById(groupId);
