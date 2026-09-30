import { IngestionConnector } from '@components/integrations/catalog/types';
import { compareCalVer } from './compareCalVer';

type ConnectorVersionEntry = {
  support_version?: string | null;
};

type CompatibleConnector = {
  support_version?: IngestionConnector['support_version'] | null;
  versions?: ConnectorVersionEntry[] | null;
};

export const getMinimumPlatformVersion = (connector: CompatibleConnector | null | undefined) => {
  if (!connector) {
    return null;
  }

  const versions = connector.versions?.length
    ? connector.versions
    : [{ support_version: connector.support_version ?? null }];

  let minimumPlatformVersion: string | null = null;

  for (const versionEntry of versions) {
    const entryMinimumVersion = versionEntry.support_version;
    if (!entryMinimumVersion) {
      continue;
    }

    if (!minimumPlatformVersion) {
      minimumPlatformVersion = entryMinimumVersion;
      continue;
    }

    const comparison = compareCalVer(entryMinimumVersion, minimumPlatformVersion);
    if (comparison !== null && comparison < 0) {
      minimumPlatformVersion = entryMinimumVersion;
    }
  }

  return minimumPlatformVersion;
};
