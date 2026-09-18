import { IngestionConnector } from '@components/integrations/catalog/types';
import { compareCalVer } from './compareCalVer';

type ConnectorVersionEntry = {
  support_version?: string | null;
  min_version?: string | null;
  min_platform_version?: string | null;
};

type CompatibleConnector = {
  support_version?: IngestionConnector['support_version'] | null;
  versions?: ConnectorVersionEntry[] | null;
};

const getEntryMinimumVersion = (entry: ConnectorVersionEntry) => {
  return entry.min_platform_version ?? entry.min_version ?? entry.support_version ?? null;
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
    const entryMinimumVersion = getEntryMinimumVersion(versionEntry);
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