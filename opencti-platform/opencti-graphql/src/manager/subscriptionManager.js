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
import { TYPE_LOCK_ERROR } from '../config/errors';

// Expired manager responsible to monitor expired elements
// In order to change the revoked attribute to true
// Each API will start is manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('subscription_scheduler:interval');
const SUBSCRIPTION_MANAGER_KEY = conf.get('subscription_scheduler:lock_key');

const defaultCrons = ['5-minutes', '1-hours', '24-hours', '1-weeks', '1-months'];

const subscriptionHandler = async () => {
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([SUBSCRIPTION_MANAGER_KEY]);
    // Execute the cleaning
    const callback = async (elements) => {
      logApp.debug(`[OPENCTI-MODULE] Subscription manager will send reports for ${elements.length} subscriptions`);
      const concurrentSend = async (element) => {
        let mailContent;
        try {
          mailContent = await generateDigestForSubscription(element);
        } catch (e) {
          logApp.error('[OPENCTI-MODULE] Subscription manager failed to generate the digest', { element, error: e });
        }
        try {
          if (mailContent) {
            await sendMail(mailContent);
          } else {
            logApp.debug('[OPENCTI-MODULE] Nothing to send', { element });
          }
        } catch (e) {
          logApp.error('[OPENCTI-MODULE] Subscription manager failed to send the email', { error: e });
        }
        await patchAttribute(SYSTEM_USER, element.id, element.entity_type, { last_run: now() });
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
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.info('[OPENCTI-MODULE] Subscription manager already in progress by another API');
    } else {
      logApp.error('[OPENCTI-MODULE] Subscription manager failed to start', { error: e });
    }
  } finally {
    logApp.debug('[OPENCTI-MODULE] Subscription manager done');
    if (lock) await lock.unlock();
  }
};

const initSubscriptionManager = () => {
  let scheduler;
  return {
    start: () => {
      logApp.info('[OPENCTI-MODULE] Running subscription manager');
      scheduler = setIntervalAsync(async () => {
        await subscriptionHandler();
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
const subscriptionManager = initSubscriptionManager();

export default subscriptionManager;
