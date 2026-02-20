import { type BasicStoreEntityAuthenticationProvider, ENTITY_TYPE_AUTHENTICATION_PROVIDER } from './authenticationProvider-types';
import { refreshStrategy, registerStrategy, unregisterStrategy } from './providers';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { pubSubSubscription } from '../../database/redis';
import { logApp, NODE_INSTANCE_ID, TOPIC_PREFIX } from '../../config/conf';

let authenticationPuSubEdit: { topic: string; unsubscribe: () => void };
let authenticationPuSubAdd: { topic: string; unsubscribe: () => void };
let authenticationPuSubDelete: { topic: string; unsubscribe: () => void };
/**
 * This listener is running on all cluster nodes.
 * When an authentication is changes, all nodes listen to that event in order to update authentication on all nodes.
 */

export const onAuthenticationMessageEdit = async (event: { instance: BasicStoreEntity }) => {
  logApp.info(`[OPENCTI-MODULE] Authentication got edit event. ${event.instance.id} on node ${NODE_INSTANCE_ID}`);
  try {
    if (event.instance.entity_type === ENTITY_TYPE_AUTHENTICATION_PROVIDER) {
      const providerEntity = event.instance as BasicStoreEntityAuthenticationProvider;
      await refreshStrategy(providerEntity);
    } else {
      logApp.warn('Entity cannot be sent to Authentication PubSubListener', { type: event.instance.entity_type });
    }
  } catch (error) {
    logApp.error('Error updating authentication ', { cause: error, from: 'authenticationProviderListener', nodeId: NODE_INSTANCE_ID, providerId: event.instance.id });
  }
};

export const onAuthenticationMessageDelete = async (event: { instance: BasicStoreEntity }) => {
  logApp.info(`[OPENCTI-MODULE] Authentication got delete event. ${event.instance.id} on node ${NODE_INSTANCE_ID}`);
  try {
    if (event.instance.entity_type === ENTITY_TYPE_AUTHENTICATION_PROVIDER) {
      const providerEntity = event.instance as BasicStoreEntityAuthenticationProvider;
      await unregisterStrategy(providerEntity);
    } else {
      logApp.warn('Entity cannot be sent to Authentication PubSubListener', { type: event.instance.entity_type });
    }
  } catch (error) {
    logApp.error('Error updating authentication ', { cause: error, from: 'authenticationProviderListener', nodeId: NODE_INSTANCE_ID, providerId: event.instance.id });
  }
};

export const onAuthenticationMessageAdd = async (event: { instance: BasicStoreEntity }) => {
  logApp.info(`[OPENCTI-MODULE] Authentication got add event. ${event.instance.id} on node ${NODE_INSTANCE_ID}`);
  try {
    if (event.instance.entity_type === ENTITY_TYPE_AUTHENTICATION_PROVIDER) {
      const providerEntity = event.instance as BasicStoreEntityAuthenticationProvider;
      await registerStrategy(providerEntity);
    } else {
      logApp.warn('Entity cannot be sent to Authentication PubSubListener', { type: event.instance.entity_type });
    }
  } catch (error) {
    logApp.error('Error updating authentication ', { cause: error, from: 'authenticationProviderListener', nodeId: NODE_INSTANCE_ID, providerId: event.instance.id });
  }
};

const initAuthenticationListener = () => {
  return {
    init: () => {}, // Use for testing
    start: async () => {
      authenticationPuSubAdd = await pubSubSubscription<{ instance: StoreEntity }>(`${TOPIC_PREFIX}ENTITY_TYPE_AUTHENTICATION_PROVIDER_ADD_TOPIC`, onAuthenticationMessageAdd);
      authenticationPuSubEdit = await pubSubSubscription<{ instance: StoreEntity }>(`${TOPIC_PREFIX}ENTITY_TYPE_AUTHENTICATION_PROVIDER_EDIT_TOPIC`, onAuthenticationMessageEdit);
      authenticationPuSubDelete = await pubSubSubscription<{ instance: StoreEntity }>(`${TOPIC_PREFIX}ENTITY_TYPE_AUTHENTICATION_PROVIDER_DELETE_TOPIC`, onAuthenticationMessageDelete);
      logApp.info('[OPENCTI-MODULE] Authentication pub sub listener initialized');
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping Authentication pub sub listener');
      try {
        authenticationPuSubAdd.unsubscribe();
        authenticationPuSubEdit.unsubscribe();
        authenticationPuSubDelete.unsubscribe();
      } catch { /* dont care */ }
      return true;
    },
  };
};
const authenticationProviderListener = initAuthenticationListener();

export default authenticationProviderListener;
