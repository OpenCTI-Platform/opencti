import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { Promise } from 'bluebird';
import { lockResource } from '../database/redis';
import { elList, ES_MAX_CONCURRENCY } from '../database/engine';
import { READ_DATA_INDICES, READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { prepareDate } from '../utils/format';
import { patchAttribute } from '../database/middleware';
import conf, { ACCOUNT_STATUS_EXPIRED, booleanConf, logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { userEditField } from '../domain/user';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';

// Expired manager responsible to monitor expired elements
// In order to change the revoked attribute to true
// Each API will start is manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('expiration_scheduler:interval');
const EXPIRED_MANAGER_KEY = conf.get('expiration_scheduler:lock_key');
let running = false;

const revokedInstances = async (context) => {
  const callback = async (elements) => {
    logApp.info(`[OPENCTI] Expiration manager will revoke ${elements.length} elements`);
    const concurrentUpdate = async (element) => {
      const patch = { revoked: true };
      // For indicator, we also need to force x_opencti_detection to false
      if (element.entity_type === ENTITY_TYPE_INDICATOR) {
        patch.x_opencti_detection = false;
      }
      await patchAttribute(context, SYSTEM_USER, element.id, element.entity_type, patch);
    };
    await Promise.map(elements, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  };
  const filters = {
    mode: 'and',
    filters: [
      { key: 'valid_until', values: [prepareDate()], operator: 'lt' },
      { key: 'revoked', values: [false] },
    ],
    filterGroups: [],
  };
  const opts = { filters, noFiltersChecking: true, connectionFormat: false, callback };
  await elList(context, SYSTEM_USER, READ_DATA_INDICES, opts);
};

const expiredAccounts = async (context) => {
  // Execute the cleaning
  const callback = async (elements) => {
    logApp.info(`[OPENCTI] Expiration manager will expire ${elements.length} users`);
    const concurrentUpdate = async (element) => {
      const inputs = [{ key: 'account_status', value: [ACCOUNT_STATUS_EXPIRED] }];
      await userEditField(context, SYSTEM_USER, element.internal_id, inputs);
    };
    await Promise.map(elements, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  };
  const filters = {
    mode: 'and',
    filters: [
      { key: 'entity_type', values: [ENTITY_TYPE_USER] },
      { key: 'account_status', values: [ACCOUNT_STATUS_EXPIRED], operator: 'not_eq' },
      { key: 'account_lock_after_date', values: [prepareDate()], operator: 'lt' },
    ],
    filterGroups: [],
  };
  const opts = { filters, connectionFormat: false, callback };
  await elList(context, SYSTEM_USER, [READ_INDEX_INTERNAL_OBJECTS], opts);
};

const expireHandler = async () => {
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([EXPIRED_MANAGER_KEY], { retryCount: 0 });
    running = true;
    const context = executionContext('expiration_manager');
    const revokedInstancesPromise = revokedInstances(context);
    const expiredAccountsPromise = expiredAccounts(context);
    await Promise.all([revokedInstancesPromise, expiredAccountsPromise]);
  } catch (e) {
    if (e.extensions.name === TYPE_LOCK_ERROR) {
      logApp.debug('[OPENCTI-MODULE] Expiration manager already started by another API');
    } else {
      logApp.error(e, { manager: 'EXPIRATION_SCHEDULER' });
    }
  } finally {
    running = false;
    logApp.debug('[OPENCTI-MODULE] Expiration manager done');
    if (lock) await lock.unlock();
  }
};

const initExpiredManager = () => {
  let scheduler;
  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Starting expiration manager');
      scheduler = setIntervalAsync(async () => {
        await expireHandler();
      }, SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'EXPIRATION_SCHEDULER',
        enable: booleanConf('expiration_scheduler:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping expiration manager');
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const expiredManager = initExpiredManager();

export default expiredManager;
