import { IngestionConnector } from '@components/integrations/catalog/types';

type DeployableConnector = {
  manager_supported?: IngestionConnector['manager_supported'] | null;
  compatibility?: IngestionConnector['compatibility'] | null;
};

// Compatibility with the platform version is computed by the backend, with the same check as the deployment
export const canDeployConnector = (connector: DeployableConnector | null | undefined) => {
  if (connector?.manager_supported !== true) {
    return false;
  }
  return connector.compatibility?.is_compatible !== false;
};
