import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { Promise } from 'bluebird';
import { lockResource } from '../database/redis';
import { elList, ES_MAX_CONCURRENCY } from '../database/engine';
import { READ_PLATFORM_INDICES } from '../database/utils';
import { hoursAgo, minutesAgo, now, prepareDate, utcDate } from '../utils/format';
import conf, { logApp } from '../config/conf';
import { SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_USER_SUBSCRIPTION } from '../schema/internalObject';
import { generateDigestForSubscription } from '../domain/userSubscription';
import { sendMail } from '../database/smtp';
import { patchAttribute } from '../database/middleware';

// Expired manager responsible to monitor expired elements
// In order to change the revoked attribute to true
// Each API will start is manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('subscription_scheduler:interval');
const SUBSCRIPTION_MANAGER_KEY = conf.get('subscription_scheduler:lock_key');

const defaultCrons = ['5-minutes', '1-hours', '24-hours', '1-weeks'];

const subscriptionHandler = async () => {
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([SUBSCRIPTION_MANAGER_KEY]);
    logApp.info('[OPENCTI-MODULE] Running subscription manager');
    // Execute the cleaning
    const callback = async (elements) => {
      logApp.info(`[OPENCTI] Subscription manager will send reports for ${elements.length} subscriptions`);
      const concurrentSend = async (element) => {
        try {
          const mailContent = await generateDigestForSubscription(element);
          if (mailContent) {
            await sendMail(mailContent);
          }
          const patch = { last_run: now() };
          await patchAttribute(SYSTEM_USER, element.id, element.entity_type, patch);
        } catch (e) {
          logApp.error('[OPENCTI] Subscription manager failed to send', { error: e });
        }
      };
      await Promise.map(elements, concurrentSend, { concurrency: ES_MAX_CONCURRENCY });
    };
    // eslint-disable-next-line no-restricted-syntax
    for (const cron of defaultCrons) {
      const [number, unit] = cron.split('-');
      let date = utcDate();
      if (unit === 'minutes') {
        date = minutesAgo(number);
      } else if (unit === 'hours') {
        date = hoursAgo(number);
      }
      const filters = [
        { key: 'entity_type', values: [ENTITY_TYPE_USER_SUBSCRIPTION] },
        { key: 'cron', values: [cron] },
        { key: 'last_run', values: [prepareDate(date)], operator: 'lt' },
      ];
      const opts = { filters, connectionFormat: false, callback };
      await elList(SYSTEM_USER, READ_PLATFORM_INDICES, opts);
    }
  } catch (e) {
    // We dont care about failing to get the lock.
    logApp.info('[OPENCTI] Subscription manager already in progress by another API');
  } finally {
    logApp.debug('[OPENCTI] Subscription manager done');
    if (lock) await lock.unlock();
  }
};

const initSubscriptionManager = () => {
  let scheduler;
  return {
    start: () => {
      scheduler = setIntervalAsync(async () => {
        await subscriptionHandler();
      }, SCHEDULE_TIME);
      // Handle hot module replacement resource dispose
      if (module.hot) {
        module.hot.dispose(async () => {
          await clearIntervalAsync(scheduler);
        });
      }
    },
    shutdown: async () => {
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const subscriptionManager = initSubscriptionManager();

export default subscriptionManager;
