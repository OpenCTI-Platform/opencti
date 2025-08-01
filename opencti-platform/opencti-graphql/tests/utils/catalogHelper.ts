import * as fs from 'fs';
import * as path from 'path';

interface ConnectorContract {
  $schema: string;
  $id: string;
  title: string;
  slug: string;
  description: string;
  short_description: string;
  use_cases: string[];
  max_confidence_level: number;
  manager_supported: boolean;
  container_version: string;
  container_image: string;
  container_type: string;
  verified: boolean;
  last_verified_date: string;
  playbook_supported: boolean;
  logo: string;
  support_version: string;
  subscription_link: string;
  source_code: string;
  type: string;
  default?: Record<string, any>;
  required?: string[];
  properties?: Record<string, any>;
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
    const catalogPath = path.join(__dirname, '../../src/modules/catalog/filigran/opencti-manifest.json');
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
  getMinimalConfig(connector: ConnectorContract, overrides: Record<string, any> = {}): Array<{ key: string; value: string[] }> {
    const config: Array<{ key: string; value: string[] }> = [];

    // Start with default values
    if (connector.default) {
      Object.entries(connector.default).forEach(([key, value]) => {
        // Skip if this is an override
        if (key in overrides) return;

        // Convert value to string array format
        const stringValue = Array.isArray(value) ? value.map(String) : [String(value)];
        config.push({ key, value: stringValue });
      });
    }

    // Add overrides
    Object.entries(overrides).forEach(([key, value]) => {
      const stringValue = Array.isArray(value) ? value.map(String) : [String(value)];
      config.push({ key, value: stringValue });
    });

    // Ensure all required fields are present
    if (connector.required) {
      connector.required.forEach((requiredKey) => {
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
    return connector.required || [];
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
