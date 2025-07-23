import { importCsvConnector, importCsvConnectorRuntime } from './importCsv/importCsv-domain';
import type { AuthContext, AuthUser } from '../types/user';
import { ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR } from './importCsv/importCsv-configuration';
import { DRAFT_VALIDATION_CONNECTOR, draftValidationConnectorRuntime } from '../modules/draftWorkspace/draftWorkspace-connector';
import { getInternalQueues } from '../database/rabbitmq';
import type { Connector } from './internalConnector';

const builtInInternalConnectors = () => {
  const builtInInternalConnectorsList: Connector[] = [];
  const internalQueues = getInternalQueues();
  for (let i = 0; i < internalQueues.length; i += 1) {
    const internalQueue = internalQueues[i];
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
  builtInConnectors.push(...builtInInternalConnectors());
  return builtInConnectors;
};

export const builtInConnectors = () => {
  return [importCsvConnector(), DRAFT_VALIDATION_CONNECTOR, ...builtInInternalConnectors()];
};

export const builtInConnector = (id: string) => {
  return builtInConnectors().find((c) => c.id === id);
};
