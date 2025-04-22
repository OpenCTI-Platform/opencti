import { type ManagerDefinition, registerManager } from './managerModule';
import { executionContext } from '../utils/access';
import { logApp } from '../config/conf';

const PIR_MANAGER_ID = 'PIR_MANAGER';
const PIR_MANAGER_LABEL = 'PIR Manager';
const PIR_MANAGER_CONTEXT = 'PIR Manager';
const PIR_MANAGER_CRON_INTERVAL = 10000; // TODO PIR: use config instead
const PIR_MANAGER_CRON_LOCK_KEY = 'pir_manager_lock'; // TODO PIR: use config instead

const pirManagerHandler = async () => {
  const context = executionContext(PIR_MANAGER_CONTEXT);
  logApp.debug('[PIR POC] PIR manager handler called');
};

const PIR_MANAGER_DEFINITION: ManagerDefinition = {
  id: PIR_MANAGER_ID,
  label: PIR_MANAGER_LABEL,
  executionContext: PIR_MANAGER_CONTEXT,
  enabledByConfig: true, // TODO PIR: use config instead
  enabled(): boolean {
    return this.enabledByConfig;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  cronSchedulerHandler: {
    handler: pirManagerHandler,
    interval: PIR_MANAGER_CRON_INTERVAL,
    lockKey: PIR_MANAGER_CRON_LOCK_KEY,
  }
};

registerManager(PIR_MANAGER_DEFINITION);
