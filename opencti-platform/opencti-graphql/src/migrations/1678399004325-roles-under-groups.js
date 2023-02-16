import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';
import { findAll, findRoles, userAddRelation, userIdDeleteRelation } from '../domain/user';
import { addGroup, groupAddRelation } from '../domain/group';

export const up = async (next) => {
  const context = executionContext('migration', SYSTEM_USER);
  const start = new Date().getTime();
  logApp.info('[MIGRATION] Refacto roles under groups');
  const users = await findAll(context, context.user);
  const usersNodes = users.edges.map((user) => user.node);
  const roles = await findRoles(context, context.user);
  const rolesNodes = roles.edges.map((role) => role.node);
  let roleGroupAssociations = {};
  // eslint-disable-next-line no-restricted-syntax
  for (const role of rolesNodes) {
    const default_assignation = role.default_assignation ?? false;
    // create a group with the role
    const groupAddInput = {
      name: `${role.name}`,
      description: `group with the role ${role.name}`,
      default_assignation,
    };
    const addedGroup = await addGroup(context, context.user, groupAddInput);
    const roleRelationInput = {
      toId: role.id,
      relationship_type: 'has-role',
    };
    await groupAddRelation(context, context.user, addedGroup.id, roleRelationInput);
    roleGroupAssociations = {
      ...roleGroupAssociations,
      [role.id]: addedGroup.id,
    };
  }
  // eslint-disable-next-line no-restricted-syntax
  for (const user of usersNodes) {
    const roleIds = user['has-role'];
    if (roleIds && roleIds.length > 0) {
      // eslint-disable-next-line no-restricted-syntax
      for (const roleId of roleIds) {
        // remove the relation between the user and the role
        await userIdDeleteRelation(context, context.user, user.id, roleId, 'has-role');
        // add a relation between the user and the associated group that has been created
        const groupRelationInput = {
          relationship_type: 'member-of',
          toId: roleGroupAssociations[roleId],
        };
        await userAddRelation(context, context.user, user.id, groupRelationInput);
      }
    }
  }
  logApp.info(`[MIGRATION] Refacto roles under groups done in ${new Date() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
