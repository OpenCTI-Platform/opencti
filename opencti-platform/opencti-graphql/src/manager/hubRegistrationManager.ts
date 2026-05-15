import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, HUB_REGISTRATION_MANAGER_USER } from '../utils/access';
import { checkXTMHubConnectivity, loadAndSaveLatestNewsFeed } from '../domain/xtm-hub';
import { XtmHubRegistrationStatus } from '../generated/graphql';
import { cleanOldNewsFeedItems } from '../modules/xtm/hub/news-feed/news-feed-domain';
import moment from 'moment';

const HUB_REGISTRATION_MANAGER_ENABLED = booleanConf('hub_registration_manager:enabled', true);
const HUB_REGISTRATION_MANAGER_KEY = conf.get('hub_registration_manager:lock_key') || 'hub_registration_manager_lock';
const SCHEDULE_TIME = conf.get('hub_registration_manager:interval') || 60 * 60 * 1000; // 1 hour
const NEWS_FEED_CLEANUP_INTERVAL_VALUE = conf.get('hub_registration_manager:news_feed_cleanup_interval_value') || 180;
const NEWS_FEED_CLEANUP_INTERVAL_UNIT = conf.get('hub_registration_manager:news_feed_cleanup_interval_unit') || 'days';

/**
 * If platform is registered, calls XTM Hub backend to check if the registration data is still valid
 * Update the settings with the result.
 */
export const hubRegistrationManager = async () => {
  const context = executionContext('hub_registration_manager');
  const { status } = await checkXTMHubConnectivity(context, HUB_REGISTRATION_MANAGER_USER);
  if (status === XtmHubRegistrationStatus.Registered) {
    await loadAndSaveLatestNewsFeed(context, HUB_REGISTRATION_MANAGER_USER);
  }

  try {
    const cutoffDate = moment()
      .subtract(NEWS_FEED_CLEANUP_INTERVAL_VALUE, NEWS_FEED_CLEANUP_INTERVAL_UNIT)
      .toDate();
    const deletedCount = await cleanOldNewsFeedItems(
      context,
      HUB_REGISTRATION_MANAGER_USER,
      cutoffDate,
    );
    if (deletedCount > 0) {
      logApp.info('[XTMH] Cleaned expired news feed items', {
        deletedCount,
        cutoffDate: cutoffDate.toISOString(),
        intervalValue: NEWS_FEED_CLEANUP_INTERVAL_VALUE,
        intervalUnit: NEWS_FEED_CLEANUP_INTERVAL_UNIT,
      });
    }
  } catch (err) {
    logApp.error('[XTMH] Failed to clean expired news feed items', { cause: err });
  }
};

const HUB_REGISTRATION_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'HUB_REGISTRATION_MANAGER',
  label: 'XTM Hub registration manager',
  executionContext: 'hub_registration_manager',
  cronSchedulerHandler: {
    handler: hubRegistrationManager,
    interval: SCHEDULE_TIME,
    lockKey: HUB_REGISTRATION_MANAGER_KEY,
  },
  enabledByConfig: HUB_REGISTRATION_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(HUB_REGISTRATION_MANAGER_DEFINITION);
