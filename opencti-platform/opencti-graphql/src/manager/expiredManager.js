import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { Promise } from 'bluebird';
import { lockResource } from '../database/redis';
import { elList, ES_MAX_CONCURRENCY } from '../database/elasticSearch';
import { SYSTEM_USER } from '../domain/user';
import { READ_DATA_INDICES } from '../database/utils';
import { prepareDate } from '../utils/format';
import { patchAttribute } from '../database/middleware';
import { logger } from '../config/conf';

// Expired manager responsible to monitor expired elements
// In order to change the revoked attribute to true
// Each API will start is manager.
// When manager do it scan it take a lock and periodically renew it until the job is done.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = 5000; // Each 5 secs
const EXPIRED_MANAGER_KEY = 'expired_manager_lock';

const expireHandler = async () => {
  logger.info('[OPENCTI] Running Expiration manager');
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([EXPIRED_MANAGER_KEY]);
    logger.info('[OPENCTI] Expiration manager lock acquired');
    // Execute the cleaning
    const callback = async (elements) => {
      logger.info(`[OPENCTI] Expiration manager will clear ${elements.length} elements`);
      const concurrentUpdate = async (element) => {
        const patch = { revoked: true };
        await patchAttribute(SYSTEM_USER, element.id, element.entity_type, patch);
      };
      await Promise.map(elements, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
      await lock.extend();
    };
    const filters = [
      { key: 'valid_until', values: [prepareDate()], operator: 'lt' },
      { key: 'revoked', values: [false] },
    ];
    const opts = { filters, connectionFormat: false, callback };
    await elList(SYSTEM_USER, READ_DATA_INDICES, opts);
  } catch (e) {
    // We dont care about failing to get the lock.
    logger.info('[OPENCTI] Expiration manager already in progress by another API');
  } finally {
    logger.info('[OPENCTI] Expiration manager done');
    if (lock) await lock.unlock();
  }
};

const initExpiredManager = () => {
  let scheduler;
  return {
    start: () => {
      scheduler = setIntervalAsync(async () => {
        await expireHandler();
      }, SCHEDULE_TIME);
    },
    shutdown: () => clearIntervalAsync(scheduler),
  };
};

export default initExpiredManager;
