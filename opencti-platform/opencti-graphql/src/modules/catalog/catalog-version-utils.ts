import semver from 'semver';
import validRange from 'semver/ranges/valid.js';
import { UnsupportedError } from '../../config/errors';
import { logApp, PLATFORM_VERSION } from '../../config/conf';
import type { BasicStoreEntityCatalogContract, CatalogContractCompatibility, CatalogContractVersion } from './catalog-types';

type SupportVersionContract = Pick<BasicStoreEntityCatalogContract, 'support_version' | 'min_version' | 'max_version' | 'contract_id'>;
type ContractVersionContract = Pick<BasicStoreEntityCatalogContract, 'contract_version'>;
type SlugContract = Pick<BasicStoreEntityCatalogContract, 'slug'>;

type CompatibilityOptions = {
  platformVersion?: string;
  onUnparsableVersion?: (args: {
    contractId: string;
    field: 'support_version' | 'min_version' | 'max_version';
    version: string;
    platformVersion: string;
  }) => void;
};

const ROLLING_VERSION = 'rolling';

export const parseCatalogSemver = (version: string | null | undefined) => {
  if (!version) {
    return null;
  }
  return semver.coerce(version);
};

export const isSupportVersionCompatible = (
  contract: SupportVersionContract,
  options: CompatibilityOptions = {},
) => {
  const supportVersion = contract.support_version;
  const minVersion = contract.min_version;
  const maxVersion = contract.max_version;
  if (!supportVersion && !minVersion && !maxVersion) {
    return true;
  }
  const platformVersion = options.platformVersion ?? PLATFORM_VERSION;
  const parsedPlatformVersion = parseCatalogSemver(platformVersion);
  const reportUnparsableVersion = (
    field: 'support_version' | 'min_version' | 'max_version',
    version: string,
  ) => {
    if (options.onUnparsableVersion) {
      options.onUnparsableVersion({ contractId: contract.contract_id, field, version, platformVersion });
    } else {
      logApp.warn(`[OPENCTI-MODULE] Ignoring catalog contract with unparsable ${field}`, {
        module: 'catalog',
        contractId: contract.contract_id,
        [field]: version,
        platformVersion,
      });
    }
  };
  if (!parsedPlatformVersion) {
    throw UnsupportedError('Invalid platform version for catalog contract compatibility', { platformVersion });
  }

  if (supportVersion) {
    const validSupportRange = validRange(supportVersion);
    if (!validSupportRange) {
      reportUnparsableVersion('support_version', supportVersion);
      return false;
    }
    return semver.satisfies(parsedPlatformVersion, validSupportRange);
  }

  const parsedMinVersion = minVersion ? semver.valid(minVersion) : null;
  if (minVersion && !parsedMinVersion) {
    reportUnparsableVersion('min_version', minVersion);
    return false;
  }
  const parsedMaxVersion = maxVersion ? semver.valid(maxVersion) : null;
  if (maxVersion && !parsedMaxVersion) {
    reportUnparsableVersion('max_version', maxVersion);
    return false;
  }

  if (parsedMinVersion && semver.lt(parsedPlatformVersion, parsedMinVersion)) {
    return false;
  }
  if (parsedMaxVersion && semver.gt(parsedPlatformVersion, parsedMaxVersion)) {
    return false;
  }

  return true;
};

export const compareContractVersions = (left: string, right: string) => {
  if (left === right) {
    return 0;
  }
  if (left === ROLLING_VERSION) {
    return 1;
  }
  if (right === ROLLING_VERSION) {
    return -1;
  }
  const leftVersion = parseCatalogSemver(left);
  const rightVersion = parseCatalogSemver(right);
  if (leftVersion && rightVersion) {
    return semver.compare(leftVersion, rightVersion);
  }
  if (leftVersion) {
    return 1;
  }
  if (rightVersion) {
    return -1;
  }
  return left.localeCompare(right, undefined, { numeric: true, sensitivity: 'base' });
};

export const compareContractVersionDesc = (
  left: ContractVersionContract,
  right: ContractVersionContract,
) => {
  return -compareContractVersions(left.contract_version, right.contract_version);
};

export const filterAndSortLatestCompatibleContracts = (
  contracts: BasicStoreEntityCatalogContract[],
  options: CompatibilityOptions = {},
) => {
  return contracts
    .filter((contract) => isSupportVersionCompatible(contract, options))
    .sort(compareContractVersionDesc);
};

// Same ordering as the contracts selection, so latest_compatible_version names the exposed contract
const compareCatalogVersionDesc = (left: CatalogContractVersion, right: CatalogContractVersion) => {
  return -compareContractVersions(left.version, right.version);
};

export const getLatestCompatibleVersion = (
  versions: CatalogContractVersion[],
  options: CompatibilityOptions = {},
) => {
  // Same check as the contracts selection and the deployment
  const compatibleVersions = [...versions]
    .filter((version) => isSupportVersionCompatible({
      contract_id: version.version,
      support_version: version.support_version ?? undefined,
      min_version: version.min_version ?? undefined,
      max_version: version.max_version ?? undefined,
    }, options))
    .sort(compareCatalogVersionDesc);

  return compatibleVersions[0]?.version ?? null;
};

// Lowest platform version required by the connector, read as strictly as isSupportVersionCompatible:
// a min_version that is not valid semver makes its version incompatible, so it is never suggested
export const getMinimumPlatformVersion = (versions: CatalogContractVersion[]) => {
  const minVersions = versions
    .map((version) => semver.valid(version.min_version ?? null))
    .filter((minVersion): minVersion is string => !!minVersion);
  return minVersions.sort(semver.compare)[0] ?? null;
};

// Highest platform version supported by the connector, when every version has a max_version
export const getMaximumPlatformVersion = (versions: CatalogContractVersion[]) => {
  const maxVersions = versions.map((version) => semver.valid(version.max_version ?? null));
  if (maxVersions.length === 0 || maxVersions.some((maxVersion) => !maxVersion)) {
    return null;
  }
  return (maxVersions as string[]).sort(semver.rcompare)[0];
};

export const getLatestVersion = (versions: CatalogContractVersion[]) => {
  return [...versions].sort(compareCatalogVersionDesc)[0]?.version ?? null;
};

export const buildCatalogContractCompatibility = (
  versions: CatalogContractVersion[],
  options: CompatibilityOptions = {},
): CatalogContractCompatibility => {
  const latestCompatibleVersion = getLatestCompatibleVersion(versions, options);
  const isCompatible = latestCompatibleVersion !== null;
  const platformVersion = parseCatalogSemver(options.platformVersion ?? PLATFORM_VERSION);
  const minimumPlatformVersion = getMinimumPlatformVersion(versions);
  const parsedMinimumPlatformVersion = parseCatalogSemver(minimumPlatformVersion);
  const maximumPlatformVersion = getMaximumPlatformVersion(versions);
  return {
    is_compatible: isCompatible,
    latest_compatible_version: latestCompatibleVersion,
    // Only set when the platform is too old or too new for every version of the connector
    minimum_platform_version: !isCompatible && platformVersion && parsedMinimumPlatformVersion && semver.lt(platformVersion, parsedMinimumPlatformVersion)
      ? minimumPlatformVersion
      : null,
    maximum_platform_version: !isCompatible && platformVersion && maximumPlatformVersion && semver.gt(platformVersion, maximumPlatformVersion)
      ? maximumPlatformVersion
      : null,
  };
};

// Same version comparison as the auto-upgrade (see connector-domain), so both agree on what an update is
export const buildConnectorUpdateStatus = (
  currentVersion: string | null | undefined,
  versions: CatalogContractVersion[],
  options: CompatibilityOptions = {},
) => {
  const latestCompatibleVersion = getLatestCompatibleVersion(versions, options);
  const latestVersion = getLatestVersion(versions);
  const updateAvailable = !!(latestCompatibleVersion && currentVersion && compareContractVersions(latestCompatibleVersion, currentVersion) > 0);
  const hasNewerIncompatibleVersion = !!(updateAvailable && latestCompatibleVersion && latestVersion && compareContractVersions(latestVersion, latestCompatibleVersion) > 0);
  return {
    update_available: updateAvailable,
    latest_compatible_version: latestCompatibleVersion,
    has_newer_incompatible_version: hasNewerIncompatibleVersion,
  };
};

const mapContractToVersion = (
  contract: Pick<BasicStoreEntityCatalogContract, 'contract_version' | 'support_version' | 'min_version' | 'max_version'>,
): CatalogContractVersion => ({
  version: contract.contract_version,
  support_version: contract.support_version ?? null,
  min_version: contract.min_version ?? null,
  max_version: contract.max_version ?? null,
});

// Selects the contract to expose for each slug: the latest compatible one, which is the
// contract used at deployment (see findLatestCompatibleCatalogContractByImageName), so the
// displayed configuration matches the deployed one. When no version is compatible, the latest
// one is kept so the connector stays visible with its compatibility information.
export const selectLatestContractsBySlug = (
  contracts: Array<BasicStoreEntityCatalogContract & SlugContract & ContractVersionContract>,
  options: CompatibilityOptions = {},
) => {
  const sortedContracts = [...contracts].sort(compareContractVersionDesc);
  const selectedBySlug = new Map<string, BasicStoreEntityCatalogContract>();
  for (const contract of sortedContracts) {
    if (!selectedBySlug.has(contract.slug) && isSupportVersionCompatible(contract, options)) {
      selectedBySlug.set(contract.slug, contract);
    }
  }
  for (const contract of sortedContracts) {
    if (!selectedBySlug.has(contract.slug)) {
      selectedBySlug.set(contract.slug, contract);
    }
  }
  // Keep the order of slugs as they first appear in the sorted contracts
  const slugs = [...new Set(sortedContracts.map((contract) => contract.slug))];
  return slugs.map((slug) => selectedBySlug.get(slug) as BasicStoreEntityCatalogContract);
};

export const groupContractVersionsBySlug = (
  contracts: Array<BasicStoreEntityCatalogContract & SlugContract & ContractVersionContract>,
  keyOf: (contract: SlugContract) => string = (contract) => contract.slug,
) => {
  const versionsBySlug = new Map<string, CatalogContractVersion[]>();
  for (const contract of [...contracts].sort(compareContractVersionDesc)) {
    const key = keyOf(contract);
    const existingVersions = versionsBySlug.get(key) ?? [];
    if (existingVersions.some((version) => version.version === contract.contract_version)) {
      continue;
    }
    existingVersions.push(mapContractToVersion(contract));
    versionsBySlug.set(key, existingVersions);
  }
  return versionsBySlug;
};
