import { importCsvConnector, importCsvConnectorRuntime } from './importCsv/importCsv-domain';
import type { AuthContext, AuthUser } from '../types/user';
import { ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR } from './importCsv/importCsv-configuration';
import { DRAFT_VALIDATION_CONNECTOR, draftValidationConnectorRuntime } from '../modules/draftWorkspace/draftWorkspace-connector';
import { getInternalBackgroundTaskQueues, getInternalPlaybookQueues, getInternalSyncQueues } from '../database/rabbitmq';
import type { Connector } from './internalConnector';

const builtInInternalConnectors = async (context: AuthContext, user: AuthUser) => {
  const builtInInternalConnectorsList: Connector[] = [];
  const backgroundTaskQueues = getInternalBackgroundTaskQueues();
  const playbookQueues = await getInternalPlaybookQueues(context, user);
  const syncQueues = await getInternalSyncQueues(context, user);
  const allInternalQueues = [...backgroundTaskQueues, ...playbookQueues, ...syncQueues];
  for (let i = 0; i < allInternalQueues.length; i += 1) {
    const internalQueue = allInternalQueues[i];
    builtInInternalConnectorsList.push({
      id: internalQueue.id,
      internal_id: internalQueue.id,
      active: true,
      auto: false,
      connector_scope: internalQueue.scope,
      connector_type: internalQueue.type,
      name: internalQueue.name,
      built_in: true,
    });
  }
  return builtInInternalConnectorsList;
};

export const builtInConnectorsRuntime = async (context: AuthContext, user: AuthUser) => {
  const builtInConnectors = [];
  if (ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR) {
    const csvConnector = await importCsvConnectorRuntime(context, user);
    builtInConnectors.push(csvConnector);
  }
  builtInConnectors.push(await draftValidationConnectorRuntime());
  builtInConnectors.push(...(await builtInInternalConnectors(context, user)));
  return builtInConnectors;
};

export const builtInConnectors = async (context: AuthContext, user: AuthUser) => {
  return [importCsvConnector(), DRAFT_VALIDATION_CONNECTOR, ...(await builtInInternalConnectors(context, user))];
};

export const builtInConnector = async (context: AuthContext, user: AuthUser, id: string) => {
  return (await builtInConnectors(context, user)).find((c) => c.id === id);
};
