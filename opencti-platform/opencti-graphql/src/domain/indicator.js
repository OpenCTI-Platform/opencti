import { assoc } from 'ramda';
import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  TYPE_STIX_DOMAIN_ENTITY
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';

export const findById = indicatorId => {
  if (indicatorId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(indicatorId);
  }
  return loadEntityById(indicatorId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Indicator'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

export const addIndicator = async (user, indicator) => {
  const created = await createEntity(indicator, 'Indicator', TYPE_STIX_DOMAIN_ENTITY);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};

export const observableRefs = indicatorId => {
  return findWithConnectedRelations(
    `match $from isa Indicator; $rel(observables_aggregation:$from, soo:$to) isa observable_refs;
    $to isa Stix-Observable;
    $from has internal_id_key "${escapeString(indicatorId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
