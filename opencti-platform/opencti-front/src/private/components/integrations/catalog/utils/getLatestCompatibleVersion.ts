import { IngestionConnector } from '@components/integrations/catalog/types';
import { compareCalVer } from './compareCalVer';

type ConnectorVersionEntry = {
  version: string;
  support_version?: string | null;
  min_version?: string | null;
  min_platform_version?: string | null;
};

type CompatibleConnector = {
  container_version?: IngestionConnector['container_version'] | null;
  support_version?: IngestionConnector['support_version'] | null;
  versions?: ConnectorVersionEntry[] | null;
};

const isVersionCompatible = (minimumVersion: string | null | undefined, platformVersion: string) => {
  if (!minimumVersion) {
    return true;
  }
  const comparison = compareCalVer(minimumVersion, platformVersion);
  return comparison !== null && comparison <= 0;
};

const getEntryMinimumVersion = (entry: ConnectorVersionEntry) => {
  return entry.min_platform_version ?? entry.min_version ?? entry.support_version ?? null;
};

export const getLatestCompatibleVersion = (
  connector: CompatibleConnector | null | undefined,
  platformVersion: string | null | undefined,
) => {
  if (!connector || !platformVersion) {
    return null;
  }

  const versions = connector.versions?.length
    ? connector.versions
    : connector.container_version
      ? [{ version: connector.container_version, support_version: connector.support_version ?? null }]
      : [];

  let latestCompatibleVersion: string | null = null;

  for (const versionEntry of versions) {
    if (!isVersionCompatible(getEntryMinimumVersion(versionEntry), platformVersion)) {
      continue;
    }
    if (!latestCompatibleVersion) {
      latestCompatibleVersion = versionEntry.version;
      continue;
    }
    const comparison = compareCalVer(versionEntry.version, latestCompatibleVersion);
    if (comparison !== null && comparison > 0) {
      latestCompatibleVersion = versionEntry.version;
    }
  }

  return latestCompatibleVersion;
};
