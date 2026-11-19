import type { AuthContext, AuthUser } from '../../types/user';
import { getEntitiesMapFromCache } from '../../database/cache';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { SYSTEM_USER } from '../../utils/access';
import { getContractConfigSchemaWithoutExcludedRuntimeVars } from '../catalog/catalog-domain';
import type { BasicStoreEntityConnector } from './connector-types';
import type { ConnectorImportConfiguration } from './connector-import-schema';

const SECRET_PARAMETER_NAME = /authorization|token|key|secret|password|cookie|credential/i;

export const connectorSecretKeys = (configSchema: ReturnType<typeof getContractConfigSchemaWithoutExcludedRuntimeVars>) => {
  return Object.entries(configSchema.properties)
    .filter(([key, property]) => property.format === 'password' || SECRET_PARAMETER_NAME.test(key))
    .map(([key]) => key);
};

export const exportConnector = async (context: AuthContext, connector: BasicStoreEntityConnector): Promise<ConnectorImportConfiguration> => {
  const configSchema = getContractConfigSchemaWithoutExcludedRuntimeVars(connector.manager_contract?.config_schema);
  const secretKeys = connectorSecretKeys(configSchema);
  const configurations = connector.manager_contract_configuration ?? [];
  const users = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  // An optional non-list parameter with a default is not stored once cleared (a list is stored empty).
  // It is exported empty, so that an import keeps it cleared instead of applying its default
  const storedKeys = new Set(configurations.map(({ key }) => key));
  const clearedParameters = Object.entries(configSchema.properties)
    .filter(([key, property]) => !storedKeys.has(key) && !secretKeys.includes(key) && !configSchema.required.includes(key)
      && property.type !== 'array' && property.default !== undefined && property.default !== null)
    .map(([key]) => ({ key, value: '' }));
  return {
    name: connector.title ?? connector.name,
    catalog_id: connector.catalog_id ?? '',
    manager_contract_image: connector.manager_contract_image ?? '',
    confidence_level: users.get(connector.connector_user_id)?.user_confidence_level?.max_confidence ?? null,
    manager_contract_configuration: [
      ...configurations
        .filter(({ key, encrypted }) => !encrypted && !secretKeys.includes(key) && configSchema.properties[key])
        .map(({ key, value }) => ({ key, value: value ?? '' })),
      ...clearedParameters,
    ],
    required_at_import: secretKeys.filter((key) => configSchema.required.includes(key) || configurations.some((configuration) => configuration.key === key)).sort(),
  };
};
