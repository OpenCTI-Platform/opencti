import { Promise } from 'bluebird';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { elRawUpdateByQuery, elReplace, ES_MAX_CONCURRENCY } from '../database/engine';
import { isNotEmptyField, READ_INDEX_INTERNAL_OBJECTS, } from '../database/utils';
import { DatabaseError } from '../config/errors';
import { elList } from '../database/middleware-loader';
import { logApp } from '../config/conf';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { RELATION_HAS_ROLE } from '../schema/internalRelationship';

const message = '[MIGRATION] Migrate hidden types from role to group';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  const groups = await elList(context, SYSTEM_USER, [READ_INDEX_INTERNAL_OBJECTS], { types: [ENTITY_TYPE_GROUP] });
  const roles = await elList(context, SYSTEM_USER, [READ_INDEX_INTERNAL_OBJECTS], { types: [ENTITY_TYPE_ROLE] });
  // Retrieve all default_hidden_types by role, concat and add to group
  const updateGroup = async (group) => {
    const rolesGroup = roles.filter((role) => (role[RELATION_HAS_ROLE] ?? []).includes(group.internal_id));
    const defaultHiddenTypes = rolesGroup
      .map((role) => role.default_hidden_types)
      .flat()
      .filter((hiddenTypes) => isNotEmptyField(hiddenTypes));
    const patch = { default_hidden_types: defaultHiddenTypes };
    await elReplace(group._index, group.id, { doc: patch });
  };
  await Promise.map(groups, updateGroup, { concurrency: ES_MAX_CONCURRENCY });
  // Remove default_hidden_types for role
  const updateRoleQuery = {
    script: {
      params: { field: 'default_hidden_types' },
      source: 'ctx._source.remove(params.field)',
    },
    query: {
      term: { 'entity_type.keyword': { value: ENTITY_TYPE_ROLE } }
    },
  };
  await elRawUpdateByQuery({
    index: [READ_INDEX_INTERNAL_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateRoleQuery
  })
    .catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err });
    });

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
