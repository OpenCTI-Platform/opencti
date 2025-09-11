import * as fs from 'fs';
import * as path from 'path';

export type ConnectorType = 'INTERNAL_ENRICHMENT' | 'EXTERNAL_IMPORT' | 'INTERNAL_EXPORT_FILE' | 'INTERNAL_IMPORT_FILE';

type ConnectorTypeMap = {
  string: string;
  integer: number;
  dict: object;
  array: string[];
  boolean: boolean;
};

type ConnectorTypedProperty<K extends keyof ConnectorTypeMap = keyof ConnectorTypeMap> = {
  type: K;
  default: ConnectorTypeMap[K];
  description: string;
};

interface ConnectorContract {
  title: string,
  slug: string,
  description: string,
  short_description: string,
  logo: string,
  use_cases: string[],
  verified: boolean,
  last_verified_date: string,
  playbook_supported: boolean,
  max_confidence_level: number,
  support_version: string,
  subscription_link: string,
  source_code: string,
  manager_supported: boolean,
  container_version: string,
  container_image: string,
  container_type: ConnectorType,
  config_schema: {
    $schema: string,
    $id: string,
    type: string,
    properties: {
      [key: string]: ConnectorTypedProperty
    },
    required: string[],
    additionalProperties: boolean,
  }
}

interface Catalog {
  id: string;
  name: string;
  description: string;
  version: string;
  contracts: ConnectorContract[];
}

class CatalogHelper {
  private catalog: Catalog;

  constructor() {
    const catalogPath = path.join(__dirname, 'opencti-manifest.json');
    const catalogContent = fs.readFileSync(catalogPath, 'utf8');
    this.catalog = JSON.parse(catalogContent);
  }

  getCatalogId(): string {
    return this.catalog.id;
  }

  getConnectorBySlug(slug: string): ConnectorContract | undefined {
    return this.catalog.contracts.find((contract) => contract.slug === slug);
  }

  getConnectorByImage(image: string): ConnectorContract | undefined {
    // Handle both with and without version
    return this.catalog.contracts.find((contract) => {
      const contractImageBase = contract.container_image.split(':')[0];
      const searchImageBase = image.split(':')[0];
      return contractImageBase === searchImageBase;
    });
  }

  getAvailableConnectors(): ConnectorContract[] {
    return this.catalog.contracts.filter((contract) => contract.manager_supported);
  }

  // eslint-disable-next-line class-methods-use-this
  getMinimalConfig(connector: ConnectorContract, overrides: Record<string, any> = {}): Array<{ key: string; value: string }> {
    const config: Array<{ key: string; value: string }> = [];

    // Start with default values
    const propertiesArray = Object.entries(connector.config_schema.properties);
    const defaultValuesArray = propertiesArray.map((property) => {
      const key = property[0];
      const value = property[1];
      return [key, value.default];
    });
    const defaultValues = Object.fromEntries(defaultValuesArray);

    if (defaultValuesArray) {
      Object.entries(defaultValues).forEach(([key, value]) => {
        // Skip if this is an override
        if (key in overrides) return;

        // Convert value to string format (join arrays with comma)
        const stringValue = Array.isArray(value) ? value.join(',') : String(value);
        config.push({ key, value: stringValue });
      });
    }

    // Add overrides
    Object.entries(overrides).forEach(([key, value]) => {
      const stringValue = Array.isArray(value) ? value.join(',') : String(value);
      config.push({ key, value: stringValue });
    });

    // Ensure all required fields are present
    if (connector.config_schema.required) {
      connector.config_schema.required.forEach((requiredKey) => {
        const exists = config.some((c) => c.key === requiredKey);
        if (!exists && !overrides[requiredKey]) {
          throw new Error(`Required field ${requiredKey} is missing for connector ${connector.slug}`);
        }
      });
    }

    return config;
  }

  // eslint-disable-next-line class-methods-use-this
  getRequiredFields(connector: ConnectorContract): string[] {
    return connector.config_schema.required || [];
  }

  // eslint-disable-next-line class-methods-use-this
  isManagerSupported(connector: ConnectorContract): boolean {
    return connector.manager_supported === true;
  }

  // eslint-disable-next-line class-methods-use-this
  getConnectorType(connector: ConnectorContract): string {
    return connector.container_type;
  }

  // Get a test-safe connector (one that's verified and manager supported)
  getTestSafeConnector(): ConnectorContract {
    const safeConnectors = this.catalog.contracts.filter(
      (c) => c.manager_supported && c.verified && c.slug === 'ipinfo'
    );

    if (safeConnectors.length === 0) {
      throw new Error('No test-safe connectors found in catalog');
    }

    return safeConnectors[0];
  }

  // Get an alternative connector for testing variety
  getAlternativeTestConnector(): ConnectorContract | undefined {
    // Try to find CVE connector as an alternative
    const alternatives = this.catalog.contracts.filter(
      (c) => c.manager_supported && c.verified && c.slug === 'cve'
    );

    return alternatives[0];
  }
}

export const catalogHelper = new CatalogHelper();
export type { ConnectorContract };
