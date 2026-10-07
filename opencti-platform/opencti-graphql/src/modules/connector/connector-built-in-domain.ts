import { importCsvConnector, importCsvConnectorRuntime } from '../../connector/importCsv/importCsv-domain';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR } from '../../connector/importCsv/importCsv-configuration';
import { DRAFT_VALIDATION_CONNECTOR, draftValidationConnectorRuntime } from '../draftWorkspace/draftWorkspace-connector';
import { getInternalBackgroundTaskQueues, getInternalPlaybookQueues, getInternalSyncQueues } from './connector-rabbitmq';
import type { InternalConnector } from './connector-types';
import { pushAll } from '../../utils/arrayUtil';

// TODO Move each built-in connector to the module that owns it: https://github.com/OpenCTI-Platform/opencti/issues/18840
//  Import CSV, draft validation, background tasks, playbooks, syncs, PIRs and notifiers are clients of the connector
//  infrastructure, but the connector module currently lists them itself (here, in connector-rabbitmq.ts and in
//  connector-domain.ts), so it depends on its client modules. Moving that code to the client modules today would
//  create a circular module dependency.
//  Planned follow-up: a built-in connector registry (registerBuiltInConnector) through which each client module
//  declares its connectors, worker queues and queues to ensure, registered explicitly from platformInit.
//  The connector module would then no longer import any client module.

const builtInInternalConnectors = async (context: AuthContext, user: AuthUser) => {
  const builtInInternalConnectorsList: InternalConnector[] = [];
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
  pushAll(builtInConnectors, (await builtInInternalConnectors(context, user)));
  return builtInConnectors;
};

export const builtInConnectors = async (context: AuthContext, user: AuthUser) => {
  return [importCsvConnector(), DRAFT_VALIDATION_CONNECTOR, ...(await builtInInternalConnectors(context, user))];
};

export const builtInConnector = async (context: AuthContext, user: AuthUser, id: string) => {
  return (await builtInConnectors(context, user)).find((c) => c.id === id);
};
