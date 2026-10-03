import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, HUB_REGISTRATION_MANAGER_USER } from '../utils/access';
import { autoRegisterOpenCTIOnStartup, checkXTMHubConnectivity, loadAndSaveLatestNewsFeed } from '../domain/xtm-hub';
import { XtmHubRegistrationStatus } from '../generated/graphql';
import { cleanOldNewsFeedItems } from '../modules/xtm/hub/news-feed/news-feed-domain';
import moment from 'moment';

const HUB_REGISTRATION_MANAGER_ENABLED = booleanConf('hub_registration_manager:enabled', true);
const HUB_REGISTRATION_MANAGER_KEY = conf.get('hub_registration_manager:lock_key') || 'hub_registration_manager_lock';
const SCHEDULE_TIME = conf.get('hub_registration_manager:interval') || 60 * 60 * 1000; // 1 hour
const NEWS_FEED_CLEANUP_INTERVAL_VALUE = conf.get('hub_registration_manager:news_feed_cleanup_interval_value') || 180;
const NEWS_FEED_CLEANUP_INTERVAL_UNIT = conf.get('hub_registration_manager:news_feed_cleanup_interval_unit') || 'days';
const BOOT_DELAY = 35_000; // Run shortly after XTM One startup registration (30s)
const XTM_HUB_PLATFORM_TOKEN = process.env.XTM_HUB_PLATFORM_TOKEN?.trim();

const VALID_CLEANUP_UNITS = ['seconds', 'minutes', 'hours', 'days', 'weeks', 'months', 'years'] as const;
type ValidCleanupUnit = typeof VALID_CLEANUP_UNITS[number];

if (
  typeof NEWS_FEED_CLEANUP_INTERVAL_VALUE !== 'number'
  || !Number.isFinite(NEWS_FEED_CLEANUP_INTERVAL_VALUE)
  || NEWS_FEED_CLEANUP_INTERVAL_VALUE <= 0
) {
  throw new Error(
    `[XTMH] Invalid news_feed_cleanup_interval_value: expected a positive number, got "${NEWS_FEED_CLEANUP_INTERVAL_VALUE}"`,
  );
}
if (!VALID_CLEANUP_UNITS.includes(NEWS_FEED_CLEANUP_INTERVAL_UNIT as ValidCleanupUnit)) {
  throw new Error(
    `[XTMH] Invalid news_feed_cleanup_interval_unit: "${NEWS_FEED_CLEANUP_INTERVAL_UNIT}". Expected one of: ${VALID_CLEANUP_UNITS.join(', ')}`,
  );
}

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
      .subtract(NEWS_FEED_CLEANUP_INTERVAL_VALUE, NEWS_FEED_CLEANUP_INTERVAL_UNIT as ValidCleanupUnit)
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

export const autoRegisterOnBoot = async (platformToken: string): Promise<void> => {
  const context = executionContext('hub_registration_boot_auto_register');
  try {
    await autoRegisterOpenCTIOnStartup(context, HUB_REGISTRATION_MANAGER_USER, platformToken);
  } catch (error) {
    logApp.warn('[XTMH][AUTO-REGISTER][BOOT] Startup auto-registration manager failed', { error });
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

if (HUB_REGISTRATION_MANAGER_ENABLED && XTM_HUB_PLATFORM_TOKEN) {
  setTimeout(() => {
    void autoRegisterOnBoot(XTM_HUB_PLATFORM_TOKEN);
  }, BOOT_DELAY);
}
