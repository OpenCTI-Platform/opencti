import { IngestionConnector } from '@components/integrations/catalog/types';

type DeployableConnector = {
  manager_supported?: IngestionConnector['manager_supported'] | null;
};

export const canDeployConnector = (connector: DeployableConnector | null | undefined) => {
  return connector?.manager_supported === true;
};
