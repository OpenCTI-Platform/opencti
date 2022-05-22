import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { Promise } from 'bluebird';
import { lockResource } from '../database/redis';
import { elList, ES_MAX_CONCURRENCY } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';
import { prepareDate } from '../utils/format';
import { patchAttribute } from '../database/middleware';
import conf, { logApp } from '../config/conf';
import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';
import { SYSTEM_USER } from '../utils/access';
import { TYPE_LOCK_ERROR } from '../config/errors';

// Expired manager responsible to monitor expired elements
// In order to change the revoked attribute to true
// Each API will start is manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('expiration_scheduler:interval');
const EXPIRED_MANAGER_KEY = conf.get('expiration_scheduler:lock_key');

const expireHandler = async () => {
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([EXPIRED_MANAGER_KEY]);
    // Execute the cleaning
    const callback = async (elements) => {
      logApp.info(`[OPENCTI] Expiration manager will revoke ${elements.length} elements`);
      const concurrentUpdate = async (element) => {
        const patch = { revoked: true };
        // For indicator, we also need to force x_opencti_detection to false
        if (element.entity_type === ENTITY_TYPE_INDICATOR) {
          patch.x_opencti_detection = false;
        }
        await patchAttribute(SYSTEM_USER, element.id, element.entity_type, patch);
      };
      await Promise.map(elements, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
    };
    const filters = [
      { key: 'valid_until', values: [prepareDate()], operator: 'lt' },
      { key: 'revoked', values: [false] },
    ];
    const opts = { filters, connectionFormat: false, callback };
    await elList(SYSTEM_USER, READ_DATA_INDICES, opts);
  } catch (e) {
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.info('[OPENCTI-MODULE] Expiration manager already started by another API');
    } else {
      logApp.error('[OPENCTI-MODULE] Expiration manager failed to start', { error: e });
    }
  } finally {
    logApp.debug('[OPENCTI-MODULE] Expiration manager done');
    if (lock) await lock.unlock();
  }
};

const initExpiredManager = () => {
  let scheduler;
  return {
    start: () => {
      logApp.info('[OPENCTI-MODULE] Running Expiration manager');
      scheduler = setIntervalAsync(async () => {
        await expireHandler();
      }, SCHEDULE_TIME);
    },
    shutdown: async () => {
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const expiredManager = initExpiredManager();

export default expiredManager;
