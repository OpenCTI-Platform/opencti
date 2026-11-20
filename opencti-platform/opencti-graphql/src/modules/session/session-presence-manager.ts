import conf, { booleanConf, isFeatureEnabled, SESSION_PRESENCE_FEATURE_FLAG } from '../../config/conf';
import { type ManagerDefinition, registerManager } from '../../manager/managerModule';
import { logoutAbandonedSessions, SESSION_PRESENCE_MANAGER_ID } from './session-presence-domain';

// Logout the sessions whose last tab is gone, whichever node held their sockets
const SESSION_PRESENCE_MANAGER_ENABLED = booleanConf('session_presence_manager:enabled', true);
const SESSION_PRESENCE_MANAGER_KEY = conf.get('session_presence_manager:lock_key') || 'session_presence_manager_lock';
const SCHEDULE_TIME = conf.get('session_presence_manager:interval') || 5000;

const SESSION_PRESENCE_MANAGER_DEFINITION: ManagerDefinition = {
  id: SESSION_PRESENCE_MANAGER_ID,
  label: 'Session presence manager',
  executionContext: 'session_presence_manager',
  cronSchedulerHandler: {
    handler: logoutAbandonedSessions,
    interval: SCHEDULE_TIME,
    lockKey: SESSION_PRESENCE_MANAGER_KEY,
  },
  enabledByConfig: SESSION_PRESENCE_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

if (isFeatureEnabled(SESSION_PRESENCE_FEATURE_FLAG)) {
  registerManager(SESSION_PRESENCE_MANAGER_DEFINITION);
}
