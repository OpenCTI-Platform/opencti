import { assoc, dissoc, map, pipe } from 'ramda';
import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { addPerson } from './user';
import { ENTITY_TYPE_USER } from '../utils/idGenerator';

export const findById = async (identityId) => {
  let data = await loadEntityById(identityId, 'Identity');
  if (!data) return data;
  data = pipe(dissoc('user_email'), dissoc('password'))(data);
  return data;
};
export const findAll = async (args) => {
  const noTypes = !args.types || args.types.length === 0;
  const entityTypes = noTypes ? ['Identity'] : args.types;
  const finalArgs = assoc('parentType', 'Stix-Domain-Entity', args);
  let data = await listEntities(entityTypes, ['name', 'alias'], finalArgs);
  data = assoc(
    'edges',
    map(
      (n) => ({
        cursor: n.cursor,
        node: pipe(dissoc('user_email'), dissoc('password'))(n.node),
        relation: n.relation,
      }),
      data.edges
    ),
    data
  );
  return data;
};

export const addIdentity = async (user, identity) => {
  const identityToCreate = dissoc('type', identity);
  if (identity.type === ENTITY_TYPE_USER) {
    return addPerson(user, identityToCreate);
  }
  const created = await createEntity(user, identityToCreate, identity.type);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
