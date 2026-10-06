import type { AuthContext, AuthUser } from '../../types/user';
import type { ContractConfigInput } from '../../generated/graphql';
import type { CatalogContract } from '../catalog/catalog-types';
import { getContractConfigSchemaWithoutExcludedRuntimeVars } from '../catalog/catalog-domain';
import { findLatestCompatibleCatalogContractByImageName } from '../catalog/catalog-repository';

/** A setting a catalog connector cannot run without, as a one-click deployment has to ask for it. */
export interface ConnectorRequiredSetting {
  key: string;
  label: string;
  description: string | null;
  type: string;
  secret: boolean;
}

// The name is set by deploymentConfiguration, the id is not validated (see validateContractConfigurations)
const DEPLOYMENT_PROVIDED_SETTINGS = ['CONNECTOR_NAME', 'CONNECTOR_ID'];

/**
 * Configuration of a one-click deployment: the settings given in the dialog, and the connector name, which the contract
 * may require without a default and the dialog does not ask for. The platform passes the name of the connector at run time.
 */
export const deploymentConfiguration = (configuration: ContractConfigInput[], name: string): ContractConfigInput[] => [
  ...configuration.filter(({ key }) => key !== 'CONNECTOR_NAME'),
  { key: 'CONNECTOR_NAME', value: name },
];

/**
 * Settings of a contract that a deployment must provide: required, without a default value and not deprecated, like
 * the required fields of the catalog deployment form.
 */
export const requiredSettingsOfContract = (configSchema: CatalogContract['config_schema'] | null | undefined): ConnectorRequiredSetting[] => {
  const schema = getContractConfigSchemaWithoutExcludedRuntimeVars(configSchema);
  const properties = schema.properties as Record<string, Record<string, unknown> | undefined>;
  return schema.required.flatMap((key) => {
    const property = properties[key];
    if (!property || DEPLOYMENT_PROVIDED_SETTINGS.includes(key) || property.deprecated === true) {
      return [];
    }
    if (property.default !== undefined && property.default !== null) {
      return [];
    }
    const declaredType = Array.isArray(property.type) ? property.type.find((type) => type !== 'null') : property.type;
    return [{
      key,
      label: typeof property.title === 'string' && property.title.length > 0 ? property.title : key,
      description: typeof property.description === 'string' && property.description.length > 0 ? property.description : null,
      type: typeof declaredType === 'string' ? declaredType : 'string',
      secret: property.format === 'password',
    }];
  });
};

const settingsByContext = new WeakMap<AuthContext, Map<string, Promise<ConnectorRequiredSetting[]>>>();

/** Required settings of the latest local catalog contract of an image compatible with the platform, once per request. */
export const requiredSettingsOfImage = (context: AuthContext, user: AuthUser, image: string | null | undefined): Promise<ConnectorRequiredSetting[]> => {
  if (!image) {
    return Promise.resolve([]);
  }
  let memo = settingsByContext.get(context);
  if (!memo) {
    memo = new Map();
    settingsByContext.set(context, memo);
  }
  const cached = memo.get(image);
  if (cached) {
    return cached;
  }
  const resolution = findLatestCompatibleCatalogContractByImageName(context, user, image)
    .then((contract) => (contract ? requiredSettingsOfContract(contract.config_schema) : []));
  memo.set(image, resolution);
  return resolution;
};
