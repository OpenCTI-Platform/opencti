import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';
import { findAll as findUsers, findRoles, userAddRelation, userIdDeleteRelation } from '../domain/user';
import { addGroup, findAll as findGroups, groupAddRelation } from '../domain/group';

export const up = async (next) => {
  const context = executionContext('migration', SYSTEM_USER);
  const start = new Date().getTime();
  logApp.info('[MIGRATION] Refacto roles under groups');
  const [users, roles, groups] = await Promise.all([findUsers(context, context.user), findRoles(context, context.user), findGroups(context, context.user)]);
  const usersNodes = users.edges.map((user) => user.node);
  const rolesNodes = roles.edges.map((role) => role.node);
  const groupsNames = groups.edges.map((group) => group.node).map((group) => group.name);
  let roleGroupAssociations = {};
  await Promise.all(rolesNodes.map(async (role) => {
    const default_assignation = role.default_assignation ?? false;
    // create a group with the role
    const groupAddInput = {
      name: groupsNames.includes(role.name) ? `${role.name} (migration)` : `${role.name}`,
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
  }));
  await Promise.all(usersNodes.map(async (user) => {
    const roleIds = user['has-role'];
    if (roleIds && roleIds.length > 0) {
      await Promise.all(roleIds.map(async (roleId) => {
        // remove the relation between the user and the role
        await userIdDeleteRelation(context, context.user, user.id, roleId, 'has-role');
        // add a relation between the user and the associated group that has been created
        const groupRelationInput = {
          relationship_type: 'member-of',
          toId: roleGroupAssociations[roleId],
        };
        await userAddRelation(context, context.user, user.id, groupRelationInput);
      }));
    }
  }));
  logApp.info(`[MIGRATION] Refacto roles under groups done in ${new Date() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
