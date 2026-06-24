// region dynamic modules
import conf, {
  ENABLED_API,
  ENABLED_CONNECTOR_MANAGER,
  ENABLED_EXPIRED_MANAGER,
  ENABLED_FILE_INDEX_MANAGER,
  ENABLED_HISTORY_MANAGER,
  ENABLED_INGESTION_MANAGER,
  ENABLED_NOTIFICATION_MANAGER,
  ENABLED_PLAYBOOK_MANAGER,
  ENABLED_PUBLISHER_MANAGER,
  ENABLED_RULE_ENGINE,
  ENABLED_SYNC_MANAGER,
  ENABLED_TASK_SCHEDULER,
  logApp,
} from './config/conf';
import httpServer from './http/httpServer';
import expiredManager from './manager/expiredManager';
import connectorManager from './manager/connectorManager';
import { ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR } from './connector/importCsv/importCsv-configuration';
import importCsvConnector from './connector/importCsv/importCsv-connector';
import taskManager from './manager/taskManager';
import ruleEngine from './manager/ruleManager';
import syncManager from './manager/syncManager';
import ingestionManager from './manager/ingestionManager';
import historyManager from './manager/historyManager';
import notificationManager from './manager/notificationManager';
import publisherManager from './manager/publisherManager';
import playbookManager from './manager/playbookManager/playbookManager';
import { isAttachmentProcessorEnabled } from './database/engine';
import fileIndexManager from './manager/fileIndexManager';
import { shutdownAllManagers, startAllManagers } from './manager/managerModule';
import clusterManager from './manager/clusterManager';
import activityListener from './manager/activityListener';
import activityManager from './manager/activityManager';
import draftValidationConnector from './modules/draftWorkspace/draftWorkspace-connector';
import authenticationProviderListener from './modules/authenticationProvider/authenticationProvider-listener';
import supportPackageListener from './modules/support/supportPackage-listener';

export const startModules = async () => {
  const startingPromises = [];

  // region API initialization
  if (ENABLED_API) {
    await httpServer.start();
    logApp.info(`[OPENCTI] API ready on port ${conf.get('app:port')}`);
  } else {
    logApp.info('[OPENCTI] API not started (disabled by configuration)');
  }
  // endregion

  // region Expiration manager
  if (ENABLED_EXPIRED_MANAGER) {
    startingPromises.push(expiredManager.start());
  } else {
    logApp.info('[OPENCTI-MODULE] Expiration manager not started (disabled by configuration)');
  }
  // endregion

  // region connector manager
  if (ENABLED_CONNECTOR_MANAGER) {
    startingPromises.push(connectorManager.start());
  } else {
    logApp.info('[OPENCTI-MODULE] Connector manager not started (disabled by configuration)');
  }
  // endregion

  // region import csv built in connector
  if (ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR) {
    startingPromises.push(importCsvConnector.start());
  } else {
    logApp.info('[OPENCTI-MODULE] Connector built in manager not started (disabled by configuration)');
  }
  // endregion

  // region draft validation built in connector
  startingPromises.push(draftValidationConnector.start());
  // endregion

  // region Task manager
  if (ENABLED_TASK_SCHEDULER) {
    startingPromises.push(taskManager.start());
  } else {
    logApp.info('[OPENCTI-MODULE] Task manager not started (disabled by configuration)');
  }
  // endregion

  // region Inference engine
  if (ENABLED_RULE_ENGINE) {
    startingPromises.push(ruleEngine.start());
  } else {
    logApp.info('[OPENCTI-MODULE] Rule engine not started (disabled by configuration)');
  }
  // endregion

  // region Sync manager
  if (ENABLED_SYNC_MANAGER) {
    startingPromises.push(syncManager.start());
  } else {
    logApp.info('[OPENCTI-MODULE] Sync manager not started (disabled by configuration)');
  }
  if (ENABLED_INGESTION_MANAGER) {
    startingPromises.push(ingestionManager.start());
  } else {
    logApp.info('[OPENCTI-MODULE] Ingestion manager not started (disabled by configuration)');
  }
  // endregion

  // region History manager
  if (ENABLED_HISTORY_MANAGER) {
    startingPromises.push(historyManager.start());
  } else {
    logApp.info('[OPENCTI-MODULE] History manager not started (disabled by configuration)');
  }
  // endregion

  // region notification
  if (ENABLED_NOTIFICATION_MANAGER) {
    startingPromises.push(notificationManager.start());
  } else {
    logApp.info('[OPENCTI-MODULE] Notification manager not started (disabled by configuration)');
  }
  if (ENABLED_PUBLISHER_MANAGER) {
    startingPromises.push(publisherManager.start());
  } else {
    logApp.info('[OPENCTI-MODULE] Publisher manager not started (disabled by configuration)');
  }
  // endregion

  // region playbook manager
  if (ENABLED_PLAYBOOK_MANAGER) {
    startingPromises.push(playbookManager.start());
  } else {
    logApp.info('[OPENCTI-MODULE] Playbook manager not started (disabled by configuration)');
  }
  if (ENABLED_FILE_INDEX_MANAGER && isAttachmentProcessorEnabled()) {
    startingPromises.push(fileIndexManager.start());
  } else if (ENABLED_FILE_INDEX_MANAGER && !isAttachmentProcessorEnabled()) {
    logApp.info('[OPENCTI-MODULE] File index manager not started : attachment processor is not configured.');
  } else {
    logApp.info('[OPENCTI-MODULE] File index manager not started (disabled by configuration)');
  }

  // region Audit
  startingPromises.push(activityListener.start());
  startingPromises.push(activityManager.start());
  // endregion

  startingPromises.push(supportPackageListener.start());
  startingPromises.push(authenticationProviderListener.start());

  await Promise.all(startingPromises);

  // refactoring in module in progress
  // all managers will be started only in this method
  await startAllManagers();

  // cluster manager checks all manager statuses, so better at the end
  await clusterManager.start();
};

export const shutdownModules = async () => {
  const stoppingPromises = [];
  // region API shutdown
  if (ENABLED_API) {
    stoppingPromises.push(httpServer.shutdown());
  }
  // endregion
  // region Expiration manager
  if (ENABLED_EXPIRED_MANAGER) {
    stoppingPromises.push(expiredManager.shutdown());
  }
  // endregion
  // region Connector manager
  if (ENABLED_CONNECTOR_MANAGER) {
    stoppingPromises.push(connectorManager.shutdown());
  }
  // endregion
  // region import csv built in connector
  if (ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR) {
    stoppingPromises.push(importCsvConnector.shutdown());
  }
  // endregion
  // region draft validation built in connector
  stoppingPromises.push(draftValidationConnector.shutdown());
  // endregion
  // region Task manager
  if (ENABLED_TASK_SCHEDULER) {
    stoppingPromises.push(taskManager.shutdown());
  }
  // endregion
  // region Inference engine
  if (ENABLED_RULE_ENGINE) {
    stoppingPromises.push(ruleEngine.shutdown());
  }
  // endregion
  // region Ingestion managers
  if (ENABLED_SYNC_MANAGER) {
    stoppingPromises.push(syncManager.shutdown());
  }
  if (ENABLED_INGESTION_MANAGER) {
    stoppingPromises.push(ingestionManager.shutdown());
  }
  // endregion
  // region History manager
  if (ENABLED_HISTORY_MANAGER) {
    stoppingPromises.push(historyManager.shutdown());
  }
  // endregion
  // region notification
  if (ENABLED_NOTIFICATION_MANAGER) {
    stoppingPromises.push(notificationManager.shutdown());
  }
  if (ENABLED_PUBLISHER_MANAGER) {
    stoppingPromises.push(publisherManager.shutdown());
  }
  // endregion
  // region playbook manager
  if (ENABLED_PLAYBOOK_MANAGER) {
    stoppingPromises.push(playbookManager.shutdown());
  }
  // endregion
  // region file index manager
  if (ENABLED_FILE_INDEX_MANAGER && isAttachmentProcessorEnabled()) {
    stoppingPromises.push(fileIndexManager.shutdown());
  }
  // endregion

  // endregion
  // region Cluster manager
  stoppingPromises.push(clusterManager.shutdown());
  // endregion
  // region Audit listener
  stoppingPromises.push(activityListener.shutdown());
  stoppingPromises.push(activityManager.shutdown());
  // endregion
  stoppingPromises.push(supportPackageListener.shutdown());
  stoppingPromises.push(authenticationProviderListener.shutdown());
  await Promise.all(stoppingPromises);

  // refactoring in module in progress
  // all managers will be shutdown only in this method
  await shutdownAllManagers();
};
// endregion
