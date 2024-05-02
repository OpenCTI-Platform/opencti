import { logApp, NODE_INSTANCE_ID, TOPIC_PREFIX } from '../config/conf';
import { pubSubSubscription } from '../database/redis';
import type { BasicStoreEntity, StoreEntity } from '../types/store';
import { ENTITY_TYPE_SUPPORT_PACKAGE, type StoreEntitySupportPackage } from '../modules/support/support-types';
import { registerNodeInSupportPackage, sendCurrentNodeSupportLogToS3 } from '../modules/support/support-domain';
import { executionContext, SYSTEM_USER } from '../utils/access';
import type { AuthContext } from '../types/user';
import { PackageStatus } from '../generated/graphql';
import { wait } from '../database/utils';

let context: AuthContext;

/**
 * -- Main process of listener --
 * This listener is running on all cluster nodes.
 * When a support package is requested, all nodes listen to that event in order to get local logs from all nodes.
 * @param event
 */
export const onSupportPackageMessage = async (event: { instance: BasicStoreEntity }) => {
  logApp.info(`[OPENCTI-MODULE] Support Package got event. ${event.instance.id} on node ${NODE_INSTANCE_ID}`);
  try {
    if (event.instance.entity_type === ENTITY_TYPE_SUPPORT_PACKAGE) {
      await wait(Math.floor(Math.random() * 500));
      await registerNodeInSupportPackage(context, SYSTEM_USER, event.instance.id, PackageStatus.InProgress);
      await sendCurrentNodeSupportLogToS3(context, SYSTEM_USER, event.instance as StoreEntitySupportPackage);
      await registerNodeInSupportPackage(context, SYSTEM_USER, event.instance.id, PackageStatus.Ready);
    } else {
      logApp.warn(`${event.instance.entity_type} entity cannot be sent to SupportPackage PubSubListener`);
    }
  } catch (error) {
    try {
      await registerNodeInSupportPackage(context, SYSTEM_USER, event.instance.id, PackageStatus.InError);
    } catch (errorInError) {
      // Well we cannot do much here.... elastic seems broken.
      logApp.error(errorInError, { from: 'supportListener', nodeId: NODE_INSTANCE_ID, packageId: event.instance.id });
    }
    logApp.error(error, { from: 'supportListener', nodeId: NODE_INSTANCE_ID, packageId: event.instance.id });
  }
};

const initSupportPackageListener = () => {
  return {
    init: () => {}, // Use for testing
    start: async () => {
      context = executionContext(`support_package_manager-${NODE_INSTANCE_ID}`);
      await pubSubSubscription<{ instance: StoreEntity }>(`${TOPIC_PREFIX}ENTITY_TYPE_SUPPORT_PACKAGE_EDIT_TOPIC`, onSupportPackageMessage);
      logApp.info('[OPENCTI-MODULE] Support Package pub sub listener initialized');
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping Support Package pub sub listener');
      return true;
    }
  };
};
const supportPackageListener = initSupportPackageListener();

export default supportPackageListener;
