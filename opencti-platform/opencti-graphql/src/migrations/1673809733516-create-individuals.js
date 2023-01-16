import { executionContext, SYSTEM_USER } from '../utils/access';
import { findAll } from '../domain/user';
import { addIndividual } from '../domain/individual';
import { MARKING_TLP_RED } from '../schema/identifier';

export const up = async () => {
  const context = executionContext('migration');
  const users = await findAll(context, SYSTEM_USER, { connectionFormat: false });
  for (let index = 0; index < users.length; index += 1) {
    const user = users[index];
    // Create individual
    const individual = {
      name: user.name,
      contact_information: user.user_email,
      x_opencti_firstname: user.firstname,
      x_opencti_lastname: user.lastname,
      objectMarking: [MARKING_TLP_RED]
    };
    await addIndividual(context, SYSTEM_USER, individual);
  }
};

export const down = async (next) => {
  next();
};
