import { logApp, PLATFORM_VERSION } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { isCatalogManagerEnabled } from '../catalog/catalog-manager';
import { redisGetManagedConnectorAutoUpgradeStatus } from './connector-redis';

// TODO Remove this startup readiness gate once OpenCTI and connector catalog
// releases are fully decoupled. It currently relies on PLATFORM_VERSION because
// a platform upgrade still implies that managed connectors may need upgrading.
const MANAGED_CONNECTOR_AUTO_UPGRADE_TIMEOUT = 90_000;
const MANAGED_CONNECTOR_AUTO_UPGRADE_POLL_INTERVAL = 5_000;
const waitForNextPoll = (delay: number) => new Promise((resolve) => {
  setTimeout(resolve, delay);
});

export const waitForManagedConnectorAutoUpgrade = async () => {
  if (!isCatalogManagerEnabled()) {
    return;
  }
  const timeoutAt = Date.now() + MANAGED_CONNECTOR_AUTO_UPGRADE_TIMEOUT;
  while (Date.now() < timeoutAt) {
    const status = await redisGetManagedConnectorAutoUpgradeStatus();
    const isCurrentPlatformVersion = status?.platformVersion === PLATFORM_VERSION;
    if (isCurrentPlatformVersion && status?.status === 'ready') {
      return;
    }
    if (isCurrentPlatformVersion && status?.status === 'failed') {
      logApp.warn('[OPENCTI-MODULE] Managed connector auto-upgrade failed, using persisted connector snapshots', {
        module: 'connector',
        cause: status.error,
      });
      return;
    }
    await waitForNextPoll(Math.min(MANAGED_CONNECTOR_AUTO_UPGRADE_POLL_INTERVAL, timeoutAt - Date.now()));
  }
  throw FunctionalError('Managed connector auto-upgrade timed out', {
    timeout: MANAGED_CONNECTOR_AUTO_UPGRADE_TIMEOUT,
  });
};
