import { IngestionConnector } from '@components/integrations/catalog/types';
import { getLatestCompatibleVersion } from './getLatestCompatibleVersion';

type DeployableConnector = {
  manager_supported?: IngestionConnector['manager_supported'] | null;
  support_version?: IngestionConnector['support_version'] | null;
  container_version?: IngestionConnector['container_version'] | null;
  versions?: Array<{
    version: string;
    support_version?: string | null;
    min_version?: string | null;
    min_platform_version?: string | null;
  }> | null;
};

export const canDeployConnector = (
  connector: DeployableConnector | null | undefined,
  platformVersion?: string | null,
) => {
  if (connector?.manager_supported !== true) {
    return false;
  }

  if (!platformVersion) {
    return true;
  }

  return getLatestCompatibleVersion(connector, platformVersion) !== null;
};
