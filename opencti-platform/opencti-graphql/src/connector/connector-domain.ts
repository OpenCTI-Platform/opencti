import { importCsvConnector, importCsvConnectorRuntime } from './importCsv/importCsv-domain';
import type { AuthContext, AuthUser } from '../types/user';
import { ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR } from './importCsv/importCsv-configuration';
import { DRAFT_VALIDATION_CONNECTOR, draftValidationConnectorRuntime } from '../modules/draftWorkspace/draftWorkspace-connector';

export const builtInConnectorsRuntime = async (context: AuthContext, user: AuthUser) => {
  const builtInConnectors = [];
  if (ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR) {
    const csvConnector = await importCsvConnectorRuntime(context, user);
    builtInConnectors.push(csvConnector);
  }
  builtInConnectors.push(await draftValidationConnectorRuntime());
  return builtInConnectors;
};

export const builtInConnectors = () => {
  return [importCsvConnector(), DRAFT_VALIDATION_CONNECTOR];
};

export const builtInConnector = (id: string) => {
  return builtInConnectors().find((c) => c.id === id);
};
