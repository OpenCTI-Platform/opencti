import { v4 as uuid } from 'uuid';
import { map } from 'ramda';
import { executeWrite } from '../database/grakn';
import { createBasicRolesAndCapabilities } from '../initialization';
import { assignRoleToUser, findAll as findAllUsers, ROLE_DEFAULT, SYSTEM_USER, userEditField } from '../domain/user';
import { logger } from '../config/conf';

export const up = async (next) => {
  try {
    // Remove user_permission and platform settings
    await executeWrite(async (wTx) => {
      await wTx.tx.query('undefine user_permission sub relation;');
      await wTx.tx.query('match $x isa platform_external_auth; delete $x;');
      await wTx.tx.query('undefine platform_external_auth sub attribute;');
      await wTx.tx.query('match $x isa platform_registration; delete $x;');
      await wTx.tx.query('undefine platform_registration sub attribute;');
      await wTx.tx.query('match $x isa platform_demo; delete $x;');
      await wTx.tx.query('undefine platform_demo sub attribute;');
    });
    // Migrate all users to assign roles user and admin
    await createBasicRolesAndCapabilities();
    // Migrate current users.
    // -- Default role for all (admin included)
    const data = await findAllUsers();
    const users = data && map((e) => e.node, data.edges);
    await Promise.all(map((u) => assignRoleToUser(u.id, ROLE_DEFAULT), users));
    // New field user_email
    await Promise.all(
      map((u) => {
        if (u.email) {
          userEditField(SYSTEM_USER, u.id, { key: 'external', value: [false] });
          return userEditField(SYSTEM_USER, u.id, { key: 'user_email', value: [u.email] });
        }
        return userEditField(SYSTEM_USER, u.id, { key: 'user_email', value: [`${uuid()}@mail.com`] });
      }, users)
    );
    // Remove old field email
    await executeWrite(async (wTx) => {
      await wTx.tx.query('match $x isa email; delete $x;');
      await wTx.tx.query('undefine email sub attribute;');
    });
  } catch (err) {
    logger.info(`[MIGRATION] roles_capabilities > Error ${err}`);
  }
  next();
};

export const down = async (next) => {
  next();
};
