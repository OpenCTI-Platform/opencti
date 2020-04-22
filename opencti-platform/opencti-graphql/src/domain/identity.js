import { assoc, dissoc, map, pipe } from 'ramda';
import { createEntity, listEntities, loadEntityById, loadEntityByStixId } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = async (identityId) => {
  let data;
  if (identityId.match(/[a-z-]+--[\w-]{36}/g)) {
    data = await loadEntityByStixId(identityId, 'Identity');
  } else {
    data = await loadEntityById(identityId, 'Identity');
  }
  if (!data) {
    return data;
  }
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
  const created = await createEntity(user, identityToCreate, identity.type, {
    stixIdType: identity.type !== 'Threat-Actor' ? 'identity' : 'threat-actor',
  });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
