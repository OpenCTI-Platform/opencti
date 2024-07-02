// Admin user initialization
import { v4 as uuidv4 } from 'uuid';
import semver from 'semver';
import { logApp, PLATFORM_VERSION } from './config/conf';
import { elUpdateIndicesMappings, initializeSchema, searchEngineInit } from './database/engine';
import { initializeAdminUser } from './config/providers';
import { initializeBucket, storageInit } from './database/file-storage';
import { initializeInternalQueues, rabbitMQIsAlive } from './database/rabbitmq';
import { initDefaultNotifiers } from './modules/notifier/notifier-domain';
import { checkPythonAvailability } from './python/pythonBridge';
import { lockResource, redisInit } from './database/redis';
import { ENTITY_TYPE_MIGRATION_STATUS } from './schema/internalObject';
import { applyMigration, lastAvailableMigrationTime } from './database/migration';
import { createEntity, loadEntity } from './database/middleware';
import { LockTimeoutError, TYPE_LOCK_ERROR, UnsupportedError } from './config/errors';
import { executionContext, SYSTEM_USER } from './utils/access';
import { smtpIsAlive } from './database/smtp';
import { initCreateEntitySettings } from './modules/entitySetting/entitySetting-domain';
import { initDecayRules } from './modules/decayRule/decayRule-domain';
import { initManagerConfigurations } from './modules/managerConfiguration/managerConfiguration-domain';
import { initializeData } from './database/data-initialization';

// region Platform constants
const PLATFORM_LOCK_ID = 'platform_init_lock';
// endregion

// Check every dependency
export const checkSystemDependencies = async () => {
  logApp.info('[OPENCTI] Checking dependencies statuses');
  // Check if elasticsearch is available
  await searchEngineInit();
  logApp.info('[CHECK] Search engine is alive');
  // Check if minio is here
  await storageInit();
  logApp.info('[CHECK] File engine is alive');
  // Check if RabbitMQ is here and create the logs exchange/queue
  await rabbitMQIsAlive();
  logApp.info('[CHECK] RabbitMQ engine is alive');
  // Check if redis is here
  await redisInit();
  logApp.info('[CHECK] Redis engine is alive');
  // Check if SMTP is here
  await smtpIsAlive();
  // Check if Python is available
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
  try {
    const migration = await loadEntity(context, SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
    return migration !== undefined;
  } catch {
    return false;
  }
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
    lock = await lockResource([PLATFORM_LOCK_ID]);
    const context = executionContext('platform_initialization');
    logApp.info('[INIT] Starting platform initialization');
    const alreadyExists = await isExistingPlatform(context);
    if (!alreadyExists) {
      logApp.info('[INIT] New platform detected, initialization...');
      await initializeInternalQueues();
      await initializeBucket();
      await initializeSchema();
      await initializeMigration(context);
      await initializeData(context, withMarkings);
      await initializeAdminUser(context);
      await initDefaultNotifiers(context);
    } else {
      logApp.info('[INIT] Existing platform detected, initialization...');
      await refreshMappingsAndIndices();
      await initializeInternalQueues();
      await isCompatiblePlatform(context);
      await initializeAdminUser(context);
      await applyMigration(context);
      await initCreateEntitySettings(context, SYSTEM_USER);
      await initManagerConfigurations(context, SYSTEM_USER);
      await initDecayRules(context, SYSTEM_USER);
    }
  } catch (e) {
    if (e.extensions.name === TYPE_LOCK_ERROR) {
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
