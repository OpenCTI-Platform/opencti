import { importCsvConnector, importCsvConnectorRuntime } from './importCsv/importCsv-domain';
import type { AuthContext, AuthUser } from '../types/user';

export const builtInConnectorsRuntime = async (context: AuthContext, user: AuthUser) => {
  return [await importCsvConnectorRuntime(context, user)];
};

export const builtInConnectors = () => {
  return [importCsvConnector()];
};

export const builtInConnector = (id: string) => {
  return builtInConnectors().find((c) => c.id === id);
};
