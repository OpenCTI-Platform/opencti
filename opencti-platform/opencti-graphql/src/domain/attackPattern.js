import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';
import {
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_COURSE_OF_ACTION,
  RELATION_MITIGATES,
} from '../utils/idGenerator';

export const findById = (attackPatternId) => {
  return loadEntityById(attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_ATTACK_PATTERN], ['name', 'description', 'aliases'], args);
};

export const addAttackPattern = async (user, attackPattern) => {
  const created = await createEntity(user, attackPattern, ENTITY_TYPE_ATTACK_PATTERN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const coursesOfAction = async (attackPatternId) => {
  return findWithConnectedRelations(
    `match $from isa ${ENTITY_TYPE_COURSE_OF_ACTION}, has internal_id $from_id; 
    $rel(${RELATION_MITIGATES}_from:$from, ${RELATION_MITIGATES}_to:$to) isa ${RELATION_MITIGATES};
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $to isa ${ENTITY_TYPE_ATTACK_PATTERN}, has internal_id "${escapeString(attackPatternId)}"; 
    get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
