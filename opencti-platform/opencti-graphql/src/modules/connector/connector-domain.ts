import { logApp, PLATFORM_VERSION } from '../../config/conf';
import { publishUserAction } from '../../listener/UserActionListener';
import type { AuthContext, AuthUser } from '../../types/user';
import { findLatestCompatibleCatalogContractBySlug } from '../catalog/catalog-repository';
import { mapContractEntityFieldsToEmbeddedConnectorManagerContract } from '../catalog/catalog-domain';
import { compareContractVersions } from '../catalog/catalog-version-utils';
import { findManagedConnectorsByCatalogId } from './connector-repository';
import type { BasicStoreEntityConnector } from './connector-types';
import { patchAttribute } from '../../database/middleware';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { redisGetManagedConnectorAutoUpgradeStatus, redisSetManagedConnectorAutoUpgradeStatus } from './connector-redis';

const autoUpgradeManagedConnector = async (
  context: AuthContext,
  user: AuthUser,
  managedConnector: BasicStoreEntityConnector,
) => {
  const { manager_upgrade_strategy, manager_contract } = managedConnector;
  // Currently we only support the "upgrade to latest compatible version" strategy
  const managerUpgradeStrategy = manager_upgrade_strategy ?? 'latest';
  if (managerUpgradeStrategy !== 'latest') {
    return true;
  }
  if (!manager_contract) {
    logApp.warn('[OPENCTI-MODULE] Inconsistent connector data, unable to find manager_contract on managed connector', {
      module: 'connector',
      connectorId: managedConnector.id,
    });
    return true;
  }
  const { slug, contract_version, content_hash } = manager_contract;
  try {
    const latestCompatibleContract = await findLatestCompatibleCatalogContractBySlug(context, user, slug);
    if (!latestCompatibleContract) {
      // Warning: we're running a connector that's not compatible anymore but
      // there's no replacement version compatible !
      logApp.warn('[OPENCTI-MODULE] Unable to find a compatible contract when applying auto-upgrade-to-latest-compatible strategy', {
        module: 'connector',
        connectorId: managedConnector.id,
      });
      return true;
    }
    const versionComparison = compareContractVersions(contract_version, latestCompatibleContract.contract_version);
    if (versionComparison === 0
      && content_hash === latestCompatibleContract.content_hash) {
      logApp.debug('[OPENCTI-MODULE] Managed connector already uses latest compatible version', {
        module: 'connector',
        connectorId: managedConnector.id,
        version: contract_version,
      });
      return true;
    }
    // Update connector
    const patch: Partial<BasicStoreEntityConnector> = {
      manager_contract: mapContractEntityFieldsToEmbeddedConnectorManagerContract(latestCompatibleContract),
      manager_contract_image: latestCompatibleContract.image,
    };
    await patchAttribute(context, user, managedConnector.id, ENTITY_TYPE_CONNECTOR, patch);
    if (versionComparison < 0) {
      logApp.info('[OPENCTI-MODULE] Upgraded connector to latest compatible version', {
        module: 'connector',
        connectorId: managedConnector.id,
        contractSlug: slug,
        previousVersion: contract_version,
        newVersion: latestCompatibleContract.contract_version,
      });
      // Activity log
      // Unsure how correct this is. Maybe the context_data is too big here.
      void publishUserAction({
        event_type: 'mutation',
        event_access: 'administration',
        event_scope: 'update',
        message: 'upgrades connector to latest compatible version',
        user,
        context_data: {
          entity_type: ENTITY_TYPE_CONNECTOR,
          id: managedConnector.id,
          input: {
            slug,
            previousVersion: contract_version,
            newVersion: latestCompatibleContract.contract_version,
          },
        },
      });
    } else if (versionComparison > 0) {
      logApp.info('[OPENCTI-MODULE] Downgraded connector to latest compatible version', {
        module: 'connector',
        connectorId: managedConnector.id,
        contractSlug: slug,
        previousVersion: contract_version,
        newVersion: latestCompatibleContract.contract_version,
      });
      // Activity log
      void publishUserAction({
        event_type: 'mutation',
        event_access: 'administration',
        event_scope: 'update',
        message: 'downgrades connector to latest compatible version',
        user,
        context_data: {
          entity_type: ENTITY_TYPE_CONNECTOR,
          id: managedConnector.id,
          input: {
            slug,
            previousVersion: contract_version,
            newVersion: latestCompatibleContract.contract_version,
          },
        },
      });
    } else {
      if (contract_version === 'rolling') {
        logApp.info('[OPENCTI-MODULE] Upgraded connector to latest compatible rolling', {
          module: 'connector',
          connectorId: managedConnector.id,
          contractSlug: slug,
          previousVersion: contract_version,
          newVersion: latestCompatibleContract.contract_version,
        });
      } else {
        // Shouldn't happen: either a Release issue or a logic/code error.
        logApp.warn('[OPENCTI-MODULE] Inconsistent connector data, same connector version with different contract content hash', {
          module: 'connector',
          contractSlug: slug,
          contractVersion: contract_version,
        });
      }
      // Activity log
      void publishUserAction({
        event_type: 'mutation',
        event_access: 'administration',
        event_scope: 'update',
        message: 'upgrades connector to latest compatible identical version',
        user,
        context_data: {
          entity_type: ENTITY_TYPE_CONNECTOR,
          id: managedConnector.id,
          input: {
            slug,
            previousVersion: contract_version,
            newVersion: latestCompatibleContract.contract_version,
          },
        },
      });
    }
    return true;
  } catch (exception) {
    logApp.error('[OPENCTI-MODULE] Failed to auto-upgrade connector to latest compatible version', {
      module: 'connector',
      contractSlug: slug,
      contractVersion: contract_version,
      cause: exception,
    });
    return false;
  }
};

export const autoUpgradeManagedConnectors = async (
  context: AuthContext,
  user: AuthUser,
  synchronizedCatalogIds: string[],
) => {
  const startedAt = Date.now();
  const currentStatus = await redisGetManagedConnectorAutoUpgradeStatus();
  const shouldUpdateReadiness = currentStatus?.platformVersion !== PLATFORM_VERSION
    || currentStatus.status === 'running';
  if (shouldUpdateReadiness) {
    await redisSetManagedConnectorAutoUpgradeStatus({
      status: 'running',
      platformVersion: PLATFORM_VERSION,
      startedAt,
    });
  }
  try {
    let hasErrors = false;
    for (const catalogId of synchronizedCatalogIds) {
      const managedConnectors = await findManagedConnectorsByCatalogId(context, user, catalogId);
      for (const managedConnector of managedConnectors) {
        const upgradedSuccessfully = await autoUpgradeManagedConnector(context, user, managedConnector);
        hasErrors ||= !upgradedSuccessfully;
      };
    };
    if (shouldUpdateReadiness) {
      await redisSetManagedConnectorAutoUpgradeStatus({
        status: hasErrors ? 'failed' : 'ready',
        platformVersion: PLATFORM_VERSION,
        startedAt,
        completedAt: Date.now(),
        ...(hasErrors ? { error: 'One or more managed connectors failed to auto-upgrade' } : {}),
      });
    }
    return { hasErrors };
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Failed to auto-upgrade managed connectors', {
      module: 'connector',
      cause: error,
    });
    if (shouldUpdateReadiness) {
      await redisSetManagedConnectorAutoUpgradeStatus({
        status: 'failed',
        platformVersion: PLATFORM_VERSION,
        startedAt,
        completedAt: Date.now(),
        error: error instanceof Error ? error.message : String(error),
      });
    }
    return { hasErrors: true };
  }
};
