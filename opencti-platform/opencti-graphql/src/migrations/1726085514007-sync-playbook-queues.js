import { logApp } from '../config/conf';
import { listAllEntities } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_SYNC } from '../schema/internalObject';
import { registerConnectorQueues } from '../database/rabbitmq';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';

const message = '[MIGRATION] Add playbook and sync dedicated queues';

const createQueuesForType = async (context, type) => {
  const elements = await listAllEntities(context, SYSTEM_USER, [type]);
  for (let i = 0; i < elements.length; i += 1) {
    const element = elements[i];
    await registerConnectorQueues(element.internal_id, `${type} ${element.internal_id} queue`, 'internal', type);
  }
};

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info(`${message} > started`);
  await createQueuesForType(context, ENTITY_TYPE_SYNC);
  await createQueuesForType(context, ENTITY_TYPE_PLAYBOOK);
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
