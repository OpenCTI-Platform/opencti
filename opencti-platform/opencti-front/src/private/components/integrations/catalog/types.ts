import { IngestionConnectorType } from '@components/integrations/catalog/utils/ingestionConnectorTypeMetadata';

type IngestionTypeMap = {
  string: string;
  integer: number;
  dict: object;
  array: string[];
  boolean: boolean;
};

export type IngestionTypedProperty<K extends keyof IngestionTypeMap = keyof IngestionTypeMap> = {
  type: K;
  default: IngestionTypeMap[K];
  description: string;
  format?: string;
};

export interface IngestionConnector {
  title: string;
  slug: string;
  description: string;
  short_description: string;
  logo: string;
  use_cases: string[];
  verified: boolean;
  last_verified_date: string;
  playbook_supported: boolean;
  max_confidence_level: number;
  support_version: string;
  subscription_link: string;
  source_code: string;
  manager_supported: boolean;
  container_version: string;
  container_image: string;
  container_type: IngestionConnectorType;
  config_schema: {
    $schema: string;
    $id: string;
    type: string;
    properties: {
      [key: string]: IngestionTypedProperty;
    };
    required: string[];
    additionalProperties: boolean;
  };
}
