import semver from 'semver';
import { logApp } from '../../config/conf';
import { publishUserAction } from '../../listener/UserActionListener';
import type { AuthContext, AuthUser } from '../../types/user';
import { findLatestCompatibleCatalogContractBySlug } from '../catalog/catalog-repository';
import { mapContractEntityFieldsToEmbeddedConnectorManagerContract } from '../catalog/catalog-domain';
import { findManagedConnectorsByCatalogId } from './connector-repository';
import type { BasicStoreEntityConnector } from '../../types/connector';
import { patchAttribute } from '../../database/middleware';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';

const autoUpgradeManagedConnector = async (
  context: AuthContext,
  user: AuthUser,
  managedConnector: BasicStoreEntityConnector,
) => {
  const { manager_upgrade_strategy, manager_contract } = managedConnector;
  // Currently we only support the "upgrade to latest compatible version" strategy
  if (manager_upgrade_strategy !== 'latest') {
    return;
  }
  if (!manager_contract) {
    logApp.warn('[OPENCTI-MODULE] Inconsistent connector data, unable to find manager_contract on managed connector', {
      module: 'connector',
      connectorId: managedConnector.id,
    });
    return;
  }
  const { slug, version, content_hash } = manager_contract;
  try {
    const latestCompatibleContract = await findLatestCompatibleCatalogContractBySlug(context, user, slug);
    if (!latestCompatibleContract) {
      // Warning: we're running a connector that's not compatible anymore but
      // there's no replacement version compatible !
      // TODO: stop the connector and block the restart from the UI, or delete
      // the connector ?
      return;
    }
    if (semver.eq(version, latestCompatibleContract.version)
      && content_hash === latestCompatibleContract.content_hash) {
      logApp.debug('[OPENCTI-MODULE] Managed connector already uses latest compatible version', {
        module: 'connector',
        connectorId: managedConnector.id,
        version,
      });
      return;
    }
    // Update connector
    const patch: Partial<BasicStoreEntityConnector> = {
      manager_contract: mapContractEntityFieldsToEmbeddedConnectorManagerContract(latestCompatibleContract),
      manager_contract_image: latestCompatibleContract.image,
    };
    await patchAttribute(context, user, managedConnector.id, ENTITY_TYPE_CONNECTOR, patch);
    if (semver.lt(version, latestCompatibleContract.version)) {
      logApp.info('[OPENCTI-MODULE] Upgraded connector to latest compatible version', {
        module: 'connector',
        connectorId: managedConnector.id,
        contractSlug: slug,
        previousVersion: version,
        newVersion: latestCompatibleContract.version,
      });
      // Activity log
      // Unsure how correct this is. Maybe the context_data is too big here.
      void publishUserAction({
        event_type: 'mutation',
        event_access: 'extended',
        event_scope: 'update',
        message: 'Upgraded connector to latest compatible version',
        user,
        context_data: {
          entity_type: ENTITY_TYPE_CONNECTOR,
          id: managedConnector.id,
          input: patch,
        },
      });
    } else if (semver.gt(version, latestCompatibleContract.version)) {
      logApp.info('[OPENCTI-MODULE] Downgraded connector to latest compatible version', {
        module: 'connector',
        connectorId: managedConnector.id,
        contractSlug: slug,
        previousVersion: version,
        newVersion: latestCompatibleContract.version,
      });
      // Activity log
      // Unsure how correct this is. Maybe the context_data is too big here.
      void publishUserAction({
        event_type: 'mutation',
        event_access: 'extended',
        event_scope: 'update',
        message: 'Downgraded connector to latest compatible version',
        user,
        context_data: {
          entity_type: ENTITY_TYPE_CONNECTOR,
          id: managedConnector.id,
          input: patch,
        },
      });
    } else if (semver.eq(version, latestCompatibleContract.version)) {
      // Shouldn't happen: either a Release issue or a logic/code error.
      logApp.warn('[OPENCTI-MODULE] Inconsistent connector data, same connector version with different contract content hash', {
        module: 'connector',
        contractSlug: slug,
        contractVersion: version,
      });
      // Activity log
      // Unsure how correct this is. Maybe the context_data is too big here.
      void publishUserAction({
        event_type: 'mutation',
        event_access: 'extended',
        event_scope: 'update',
        message: 'Upgraded connector to latest compatible identical version',
        user,
        context_data: {
          entity_type: ENTITY_TYPE_CONNECTOR,
          id: managedConnector.id,
          input: patch,
        },
      });
    } else {
      throw new Error('Unexpected case when comparing connector contract versions');
    }
  } catch (exception) {
    logApp.error('[OPENCTI-MODULE] Failed to auto-upgrade connector to latest compatible version', {
      module: 'connector',
      contractSlug: slug,
      contractVersion: version,
      cause: exception,
    });
  }
};

export const autoUpgradeManagedConnectors = async (
  context: AuthContext,
  user: AuthUser,
  synchedCatalogs: string[],
) => {
  for (const catalogId of synchedCatalogs) {
    const managedConnectors = await findManagedConnectorsByCatalogId(context, user, catalogId);
    for (const managedConnector of managedConnectors) {
      await autoUpgradeManagedConnector(context, user, managedConnector);
    };
  };
};
