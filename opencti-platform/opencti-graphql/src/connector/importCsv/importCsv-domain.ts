import type { AuthContext, AuthUser } from '../../types/user';
import { IMPORT_CSV_CONNECTOR } from './importCsv';
import { getCsvMapperErrorMessage } from '../../modules/internal/csvMapper/csvMapper-utils';
import type { BasicStoreEntityCsvMapper } from '../../modules/internal/csvMapper/csvMapper-types';

export const importCsvConnector = () => {
  return IMPORT_CSV_CONNECTOR;
};

export const importCsvConnectorRuntime = async (context: AuthContext, user: AuthUser) => {
  const connector = importCsvConnector();
  const configurations = connector.connector_schema_runtime_fn ? await connector.connector_schema_runtime_fn(context, user) : [];
  const configurationsFiltered: BasicStoreEntityCsvMapper[] = [];
  await Promise.all(configurations.map(async (c) => {
    const mapperErrors = await getCsvMapperErrorMessage(context, user, c);
    if (mapperErrors === null) {
      configurationsFiltered.push(c);
    }
  }));
  return ({
    ...connector,
    configurations: configurationsFiltered.map((c) => ({
      id: c.id,
      name: c.name,
      configuration: JSON.stringify(c)
    })),
  });
};
