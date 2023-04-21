import LRU from 'lru-cache';
import {
  ActionHandler,
  ActionListener,
  registerUserActionListener,
  UserAction,
} from '../listener/UserActionListener';
import { isStixCoreObject } from '../schema/stixCoreObject';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { logAudit } from '../config/conf';

// Use of this Code Software is subject to the terms of Filigran EULA
// License is currently under construction, please contact Filigran at contact@filigran.io to have more information

const initAuditManager = () => {
  const auditReadCache = new LRU({ ttl: 60 * 60 * 1000, max: 5000 }); // Read lifetime is 1 hour
  const auditLogger = (action: UserAction) => {
    const level = action.status === 'error' ? 'error' : 'info';
    logAudit._log(level, action.user, action.event_type, action.context_data);
  };
  const auditHandler: ActionListener = {
    id: 'AUDIT_MANAGER',
    next: async (action: UserAction) => {
      if (action.event_type === 'login') {
        auditLogger(action);
        const { provider } = action.context_data;
        // eslint-disable-next-line no-console
        console.log(`>>> ${action.user.user_email} login from ${provider}`);
      }
      if (action.event_type === 'logout') {
        auditLogger(action);
        // eslint-disable-next-line no-console
        console.log(`>>> ${action.user.user_email} logout`);
      }
      if (action.event_type === 'read') {
        const { id, entity_type } = action.context_data;
        const identifier = `${id}-${action.user.id}`;
        if (!auditReadCache.has(identifier)) {
          if (isStixCoreObject(entity_type) || isStixCoreRelationship(entity_type)) {
            auditLogger(action);
            // eslint-disable-next-line no-console
            console.log(`>>> ${action.user.user_email} reading ${id}/${entity_type}`);
            auditReadCache.set(identifier, undefined);
          }
        }
      }
      if (action.event_type === 'upload') {
        const { id, filename } = action.context_data;
        auditLogger(action);
        // eslint-disable-next-line no-console
        console.log(`>>> ${action.user.user_email} uploading ${id}/${filename}`);
      }
      if (action.event_type === 'download') {
        const { id, filename } = action.context_data;
        auditLogger(action);
        // eslint-disable-next-line no-console
        console.log(`>>> ${action.user.user_email} downloading ${id}/${filename}`);
      }
      if (action.event_type === 'export') {
        const { type, ids } = action.context_data;
        auditLogger(action);
        // eslint-disable-next-line no-console
        console.log(`>>> ${action.user.user_email} exporting ${type}/${ids.join(', ')}`);
      }
      if (action.event_type === 'admin') {
        const { type } = action.context_data;
        auditLogger(action);
        // eslint-disable-next-line no-console
        console.log(`>>> ${action.user.user_email} operate ${type}`);
      }
      if (action.event_type === 'unauthorized') {
        const { path } = action.context_data;
        auditLogger(action);
        // eslint-disable-next-line no-console
        console.log(`>>> ${action.user.user_email} unauthorized for ${path}`);
      }
    }
  };
  let handler: ActionHandler;
  return {
    start: async () => {
      handler = registerUserActionListener(auditHandler);
    },
    status: () => {
      return {
        id: 'AUDIT_MANAGER',
        enable: true,
        running: true,
      };
    },
    shutdown: async () => {
      if (handler) handler.unregister();
      return true;
    },
  };
};
const auditManager = initAuditManager();
export default auditManager;
