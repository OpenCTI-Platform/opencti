import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { createRelation } from '../database/middleware';
import { elLoadById } from '../database/engine';
import { isNotEmptyField } from '../database/utils';

const message = '[MIGRATION] Add bypass mandatory field to connector role';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // Resolve the role "Connector" based on standard ID
  const connectorRole = await elLoadById(context, SYSTEM_USER, 'role--b375ed46-a11c-56d5-a2d4-0c654f61eeee');

  // Add the capability
  if (isNotEmptyField(connectorRole)) {
    const byPassMandatoryAttributeCapability = await elLoadById(context, SYSTEM_USER, 'capability--767be0e4-3b1f-5073-bfea-f23f785a36d1');
    const input = { fromId: connectorRole.id, toId: byPassMandatoryAttributeCapability.id, relationship_type: 'has-capability' };
    await createRelation(context, SYSTEM_USER, input);
  }

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
