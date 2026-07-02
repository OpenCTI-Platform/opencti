// Admin user initialization
import { v4 as uuidv4 } from 'uuid';
import semver from 'semver';
import { ENABLED_FEATURE_FLAGS, logApp, PLATFORM_VERSION } from './config/conf';
import { elUpdateIndicesMappings, ES_INIT_MAPPING_MIGRATION, ES_IS_INIT_MIGRATION, initializeSchema } from './database/engine';
import { initializeBucket } from './database/raw-file-storage';
import { enforceQueuesConsistency, initializeInternalQueues } from './database/rabbitmq';
import { initDefaultNotifiers } from './modules/notifier/notifier-domain';
import { ENTITY_TYPE_MIGRATION_STATUS } from './schema/internalObject';
import { applyMigration, lastAvailableMigrationTime } from './database/migration';
import { createEntity, loadEntity } from './database/middleware';
import { ConfigurationError, LockTimeoutError, TYPE_LOCK_ERROR, UnsupportedError } from './config/errors';
import { executionContext, SYSTEM_USER } from './utils/access';
import { initCreateEntitySettings } from './modules/entitySetting/entitySetting-domain';
import { initDecayRules } from './modules/decayRule/decayRule-domain';
import { initManagerConfigurations } from './modules/managerConfiguration/managerConfiguration-domain';
import { initializeData, patchPlatformId } from './database/data-initialization';
import { initExclusionListCache } from './database/exclusionListCache';
import { initFintelTemplates } from './modules/fintelTemplate/fintelTemplate-domain';
import { lockResources } from './lock/master-lock';
import { loadEntityMetricsConfiguration } from './modules/metrics/metrics-utils';
import { initializeStreamStack } from './database/stream/stream-handler';
import { initializeAuthenticationProviders } from './modules/authenticationProvider/providers';
import { initializeAdminUser } from './domain/user';
import { CF_COMMENT_KEY, CF_SCORE_KEY, customFieldDefinitionAdd, findCustomFieldDefinitionsPaginated } from './modules/customField/custom-field-domain';
import { ADMIN_USER, testContext } from '../tests/utils/testQuery';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from './modules/case/case-incident/case-incident-types';

// region Platform constants
const PLATFORM_LOCK_ID = 'platform_init_lock';
// endregion

export const checkFeatureFlags = () => {
  if (ENABLED_FEATURE_FLAGS.length > 0) {
    logApp.info(`[FEATURE-FLAG] Activated features still in development: ${ENABLED_FEATURE_FLAGS}`);
  }
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
      await initializeStreamStack();
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
      await initializeStreamStack();
      await enforceQueuesConsistency(context, SYSTEM_USER);
      await isCompatiblePlatform(context);
      await initializeAdminUser(context);
      await applyMigration(context);
      await initCreateEntitySettings(context, SYSTEM_USER);
      await initManagerConfigurations(context, SYSTEM_USER);
      await initDecayRules(context, SYSTEM_USER);
    }

    // FIXME Hack for custom field POC, to be removed
    const currentCustomFields = await findCustomFieldDefinitionsPaginated(testContext, ADMIN_USER, { first: 50 });
    if (!currentCustomFields.edges.some((cf) => cf.node.id === CF_SCORE_KEY)) {
      const input = {
        entity_types: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT],
        field_type: 'integer',
        label: 'cf score',
        max_value: 100,
        min_value: 0,
        name: CF_SCORE_KEY,
        mandatory: false,
      };
      await customFieldDefinitionAdd(testContext, ADMIN_USER, input);
    }

    if (!currentCustomFields.edges.some((cf) => cf.node.id === CF_COMMENT_KEY)) {
      const input = {
        entity_types: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT],
        field_type: 'string',
        label: 'cf comment',
        name: CF_COMMENT_KEY,
        mandatory: false,
      };
      await customFieldDefinitionAdd(testContext, ADMIN_USER, input);
    }

    await initExclusionListCache();

    // Authentication
    await initializeAuthenticationProviders(context);

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
