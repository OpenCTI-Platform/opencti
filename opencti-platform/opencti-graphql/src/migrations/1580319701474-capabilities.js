import { executeWrite } from '../database/grakn';
import { createBasicRolesAndCapabilities } from '../initialization';

export const up = async next => {
  // Remove user_permission
  await executeWrite(async wTx => {
    await wTx.tx.query('undefine user_permission sub relation;');
  });
  // Migrate all users to assign roles user and admin
  await createBasicRolesAndCapabilities();
  // Migrate current users.
  // -- Admin role for OPENCTI_ADMIN_UUID

  // -- Default role for others

  // New field user_email

  // Remove old field email
  next();
};

export const down = async next => {
  next();
};
