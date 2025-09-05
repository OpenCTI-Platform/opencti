import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';
import { userAddRelation } from '../domain/user';
import { groupAddRelation } from '../domain/group';
import { fullEntitiesList, fullRelationsList, storeLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_USER, } from '../schema/internalObject';
import { RELATION_HAS_ROLE, RELATION_MEMBER_OF } from '../schema/internalRelationship';
import { addGroup } from '../domain/grant';
import { elDeleteElements } from '../database/engine';

export const up = async (next) => {
  logApp.info('[MIGRATION] Roles missing groups');
  const context = executionContext('migration', SYSTEM_USER);
  const start = new Date().getTime();
  const relationArgs = { fromTypes: [ENTITY_TYPE_USER] };
  const currentRolesRelations = await fullRelationsList(context, context.user, [RELATION_HAS_ROLE], relationArgs);
  // If remaining user->roles relationships available.
  if (currentRolesRelations.length > 0) {
    const roles = await fullEntitiesList(context, context.user, [ENTITY_TYPE_ROLE]);
    const groups = await fullEntitiesList(context, context.user, [ENTITY_TYPE_GROUP]);
    const groupsNames = groups.map((group) => group.name);
    // For each role, create the corresponding group
    logApp.info(`[MIGRATION] Roles missing groups creating ${roles.length} groups from roles`);
    const roleGroupAssociations = {};
    for (let i = 0; i < roles.length; i += 1) {
      const role = roles[i];
      const groupAddInput = {
        name: groupsNames.includes(role.name) ? `${role.name} (migration)` : `${role.name}`,
        description: `group with the role ${role.name}`,
        default_assignation: role.default_assignation ?? false,
      };
      const addedGroup = await addGroup(context, context.user, groupAddInput);
      // Add the relation between the role and the group
      const roleRelationInput = { toId: role.id, relationship_type: RELATION_HAS_ROLE };
      await groupAddRelation(context, context.user, addedGroup.id, roleRelationInput);
      roleGroupAssociations[role.id] = addedGroup.id;
    }
    // Remap each user to the corresponding groups
    logApp.info(`[MIGRATION] Roles missing groups remapping ${currentRolesRelations.length} roles relations`);
    for (let index = 0; index < currentRolesRelations.length; index += 1) {
      const element = currentRolesRelations[index];
      const { fromId: userId, toId: roleId } = element;
      const user = await storeLoadById(context, context.user, userId, ENTITY_TYPE_USER);
      const role = await storeLoadById(context, context.user, roleId, ENTITY_TYPE_ROLE);
      if (user && role) {
        // ignore because some stuff has been deleted from elastic
        const groupRelationInput = { relationship_type: RELATION_MEMBER_OF, toId: roleGroupAssociations[roleId] };
        await userAddRelation(context, context.user, userId, groupRelationInput);
      }
      // Delete the old relation
      await elDeleteElements(context, context.user, [element]);
    }
  }
  logApp.info(`[MIGRATION] Roles missing groups done in ${new Date() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
