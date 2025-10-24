// Admin user initialization
import { v4 as uuidv4 } from 'uuid';
import semver from 'semver';
import { ENABLED_FEATURE_FLAGS, logApp, PLATFORM_VERSION } from './config/conf';
import { elUpdateIndicesMappings, ES_INIT_MAPPING_MIGRATION, ES_IS_INIT_MIGRATION, initializeSchema, searchEngineInit } from './database/engine';
import { initializeAdminUser } from './config/providers';
import { storageInit, initializeBucket } from './database/raw-file-storage';
import { enforceQueuesConsistency, initializeInternalQueues, rabbitMQIsAlive } from './database/rabbitmq';
import { initDefaultNotifiers } from './modules/notifier/notifier-domain';
import { checkPythonAvailability } from './python/pythonBridge';
import { redisInit } from './database/redis';
import { ENTITY_TYPE_MIGRATION_STATUS } from './schema/internalObject';
import { applyMigration, lastAvailableMigrationTime } from './database/migration';
import { createEntity, loadEntity } from './database/middleware';
import { ConfigurationError, LockTimeoutError, TYPE_LOCK_ERROR, UnsupportedError } from './config/errors';
import { executionContext, SYSTEM_USER } from './utils/access';
import { smtpIsAlive } from './database/smtp';
import { initCreateEntitySettings } from './modules/entitySetting/entitySetting-domain';
import { initDecayRules } from './modules/decayRule/decayRule-domain';
import { initManagerConfigurations } from './modules/managerConfiguration/managerConfiguration-domain';
import { initializeData, patchPlatformId } from './database/data-initialization';
import { initExclusionListCache } from './database/exclusionListCache';
import { initFintelTemplates } from './modules/fintelTemplate/fintelTemplate-domain';
import { lockResources } from './lock/master-lock';
import { loadEntityMetricsConfiguration } from './modules/metrics/metrics-utils';

// region Platform constants
const PLATFORM_LOCK_ID = 'platform_init_lock';
// endregion

export const checkFeatureFlags = () => {
  if (ENABLED_FEATURE_FLAGS.length > 0) {
    logApp.info(`[FEATURE-FLAG] Activated features still in development: ${ENABLED_FEATURE_FLAGS}`);
  }
};

// Check every dependency
export const checkSystemDependencies = async () => {
  logApp.info('[OPENCTI] Checking dependencies statuses');
  // Check if elasticsearch is available
  logApp.info('[CHECK] checking if Search engine is alive');
  await searchEngineInit();
  // Check if minio is here
  logApp.info('[CHECK] Search engine ok, checking if File storage is alive');
  await storageInit();
  // Check if RabbitMQ is here and create the logs exchange/queue
  logApp.info('[CHECK] File storage ok, checking if RabbitMQ is alive');
  await rabbitMQIsAlive();
  logApp.info('[CHECK] RabbitMQ ok, checking if Redis is alive');
  // Check if redis is here
  await redisInit();
  logApp.info('[CHECK] Redis ok, checking if SMTP is alive');
  // Check if SMTP is here
  await smtpIsAlive();
  // Check if Python is available
  logApp.info('[CHECK] SMTP done, checking if python is available');
  const context = executionContext('system_dependencies');
  await checkPythonAvailability(context, SYSTEM_USER);
  logApp.info('[CHECK] Python3 is available');
  return true;
};

const refreshMappingsAndIndices = async () => {
  await elUpdateIndicesMappings();
};

const initializeMigration = async (context) => {
  logApp.info('[INIT] Creating migration structure');
  const time = lastAvailableMigrationTime();
  const lastRun = `${time}-init`;
  const migrationStatus = { internal_id: uuidv4(), lastRun };
  await createEntity(context, SYSTEM_USER, migrationStatus, ENTITY_TYPE_MIGRATION_STATUS);
};

const isExistingPlatform = async (context) => {
  const migration = await loadEntity(context, SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
  return migration !== undefined;
};

const isCompatiblePlatform = async (context) => {
  const migration = await loadEntity(context, SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
  const { platformVersion: currentVersion } = migration;
  // For old platform, version is not set yet, continue
  if (!currentVersion) return;
  // Runtime version must be >= of the stored runtime
  const runtimeVersion = semver.coerce(PLATFORM_VERSION).version;
  if (semver.lt(runtimeVersion, currentVersion)) {
    throw UnsupportedError('Your platform data are too recent to start on', { currentVersion, runtimeVersion });
  }
};

// eslint-disable-next-line
const platformInit = async (withMarkings = true) => {
  let lock;
  try {
    lock = await lockResources([PLATFORM_LOCK_ID]);
    const context = executionContext('platform_initialization');
    logApp.info('[INIT] Starting platform initialization');
    const alreadyExists = await isExistingPlatform(context);
    if (!alreadyExists) {
      logApp.info('[INIT] New platform detected, initialization...');
      await initializeInternalQueues();
      await initializeBucket();
      await initializeSchema();
      if (ES_IS_INIT_MIGRATION) {
        logApp.warn(`Templates and indices created with ${ES_INIT_MAPPING_MIGRATION} compatible mapping protection. `
            + 'This is only used to help indices reindex and migration. For retro option, please reindex, restart and then '
            + 'trigger a rollover to secure the new indices');
        process.exit(1);
      }
      await initializeMigration(context);
      await initializeData(context, withMarkings);
      await initializeAdminUser(context);
      await initDefaultNotifiers(context);
      await initFintelTemplates(context, SYSTEM_USER);
    } else {
      logApp.info('[INIT] Existing platform detected, initialization...');
      if (ES_IS_INIT_MIGRATION) {
        // noinspection ExceptionCaughtLocallyJS
        throw ConfigurationError('Internal option internal_init_mapping_migration is only available for new platform init');
      }
      await patchPlatformId(context);
      await refreshMappingsAndIndices();
      await initializeInternalQueues();
      await enforceQueuesConsistency(context, SYSTEM_USER);
      await isCompatiblePlatform(context);
      await initializeAdminUser(context);
      await applyMigration(context);
      await initCreateEntitySettings(context, SYSTEM_USER);
      await initManagerConfigurations(context, SYSTEM_USER);
      await initDecayRules(context, SYSTEM_USER);
    }
    await initExclusionListCache();

    // parse schema metrics conf to throw error on start if bad configured
    loadEntityMetricsConfiguration();
  } catch (e) {
    if (e.name === TYPE_LOCK_ERROR) {
      const reason = 'Platform cant get the lock for initialization (can be due to other instance currently migrating/initializing)';
      throw LockTimeoutError({ participantIds: [PLATFORM_LOCK_ID] }, reason);
    } else {
      throw e;
    }
  } finally {
    if (lock) {
      await lock.unlock();
      logApp.info('[INIT] Platform initialization done');
    }
  }
  return true;
};

export default platformInit;
