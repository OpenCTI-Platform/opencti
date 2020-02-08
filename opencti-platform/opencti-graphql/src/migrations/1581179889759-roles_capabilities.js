import { map } from 'ramda';
import { executeWrite } from '../database/grakn';
import { createBasicRolesAndCapabilities } from '../initialization';
import {
  assignRoleToUser,
  findAll as findAllUsers,
  OPENCTI_ADMIN_UUID,
  ROLE_ADMINISTRATOR,
  ROLE_DEFAULT,
  SYSTEM_USER,
  userEditField
} from '../domain/user';

export const up = async next => {
  // Remove user_permission
  await executeWrite(async wTx => {
    await wTx.tx.query('undefine user_permission sub relation;');
  });
  // Migrate all users to assign roles user and admin
  await createBasicRolesAndCapabilities();
  // Migrate current users.
  // -- Admin role for OPENCTI_ADMIN_UUID
  await assignRoleToUser(OPENCTI_ADMIN_UUID, ROLE_ADMINISTRATOR);
  // -- Default role for all (admin included)
  const users = await findAllUsers();
  await Promise.all(map(u => assignRoleToUser(u.id, ROLE_DEFAULT), users));
  // New field user_email
  await Promise.all(map(u => userEditField(SYSTEM_USER, u.id, { key: 'user_email', value: [u.email] }), users));
  // Remove old field email
  await executeWrite(async wTx => {
    await wTx.tx.query('undefine email sub attribute;');
  });
  next();
};

export const down = async next => {
  next();
};
