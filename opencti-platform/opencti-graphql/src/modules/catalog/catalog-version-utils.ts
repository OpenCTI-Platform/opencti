import semver from 'semver';
import { logApp, PLATFORM_VERSION } from '../../config/conf';
import type { BasicStoreEntityCatalogContract, CatalogContractCompatibility, CatalogContractVersion } from './catalog-types';

type SupportVersionContract = Pick<BasicStoreEntityCatalogContract, 'support_version' | 'contract_id'>;
type ContractVersionContract = Pick<BasicStoreEntityCatalogContract, 'contract_version'>;
type SlugContract = Pick<BasicStoreEntityCatalogContract, 'slug'>;

type CompatibilityOptions = {
  platformVersion?: string;
  onUnparsableSupportVersion?: (args: { contractId: string; supportVersion: string; platformVersion: string }) => void;
};

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
  if (!contract.support_version) {
    return true;
  }
  const platformVersion = options.platformVersion ?? PLATFORM_VERSION;
  const contractVersion = parseCatalogSemver(contract.support_version);
  const parsedPlatformVersion = parseCatalogSemver(platformVersion);
  if (!contractVersion || !parsedPlatformVersion) {
    if (options.onUnparsableSupportVersion) {
      options.onUnparsableSupportVersion({
        contractId: contract.contract_id,
        supportVersion: contract.support_version,
        platformVersion,
      });
    } else {
      logApp.warn('[OPENCTI-MODULE] Ignoring catalog contract with unparsable support version', {
        module: 'catalog',
        contractId: contract.contract_id,
        supportVersion: contract.support_version,
        platformVersion,
      });
    }
    return false;
  }
  return semver.lte(contractVersion, parsedPlatformVersion);
};

export const compareContractVersionDesc = (
  left: ContractVersionContract,
  right: ContractVersionContract,
) => {
  const leftVersion = parseCatalogSemver(left.contract_version);
  const rightVersion = parseCatalogSemver(right.contract_version);
  if (leftVersion && rightVersion) {
    return semver.rcompare(leftVersion, rightVersion);
  }
  if (leftVersion) {
    return -1;
  }
  if (rightVersion) {
    return 1;
  }
  return right.contract_version.localeCompare(left.contract_version, undefined, { numeric: true, sensitivity: 'base' });
};

export const filterAndSortLatestCompatibleContracts = (
  contracts: BasicStoreEntityCatalogContract[],
  options: CompatibilityOptions = {},
) => {
  return contracts
    .filter((contract) => isSupportVersionCompatible(contract, options))
    .sort(compareContractVersionDesc);
};

const getMinimumVersionForCatalogVersion = (version: CatalogContractVersion) => {
  return version.min_platform_version ?? version.min_version ?? version.support_version ?? null;
};

const compareCatalogVersionDesc = (left: CatalogContractVersion, right: CatalogContractVersion) => {
  const leftVersion = parseCatalogSemver(left.version);
  const rightVersion = parseCatalogSemver(right.version);
  if (leftVersion && rightVersion) {
    return semver.rcompare(leftVersion, rightVersion);
  }
  if (leftVersion) {
    return -1;
  }
  if (rightVersion) {
    return 1;
  }
  return right.version.localeCompare(left.version, undefined, { numeric: true, sensitivity: 'base' });
};

export const getLatestCompatibleVersion = (
  versions: CatalogContractVersion[],
  options: CompatibilityOptions = {},
) => {
  const platformVersion = options.platformVersion ?? PLATFORM_VERSION;
  const compatibleVersions = [...versions]
    .filter((version) => {
      const minimumVersion = getMinimumVersionForCatalogVersion(version);
      if (!minimumVersion) {
        return true;
      }
      const parsedMinimumVersion = parseCatalogSemver(minimumVersion);
      const parsedPlatformVersion = parseCatalogSemver(platformVersion);
      if (!parsedMinimumVersion || !parsedPlatformVersion) {
        return false;
      }
      return semver.lte(parsedMinimumVersion, parsedPlatformVersion);
    })
    .sort(compareCatalogVersionDesc);

  return compatibleVersions[0]?.version ?? null;
};

export const getMinimumPlatformVersion = (versions: CatalogContractVersion[]) => {
  let minimumPlatformVersion: string | null = null;

  for (const version of versions) {
    const candidateVersion = getMinimumVersionForCatalogVersion(version);
    if (!candidateVersion) {
      continue;
    }
    if (!minimumPlatformVersion) {
      minimumPlatformVersion = candidateVersion;
      continue;
    }
    const parsedCandidateVersion = parseCatalogSemver(candidateVersion);
    const parsedMinimumPlatformVersion = parseCatalogSemver(minimumPlatformVersion);
    if (parsedCandidateVersion && parsedMinimumPlatformVersion) {
      if (semver.lt(parsedCandidateVersion, parsedMinimumPlatformVersion)) {
        minimumPlatformVersion = candidateVersion;
      }
      continue;
    }
    if (candidateVersion.localeCompare(minimumPlatformVersion, undefined, { numeric: true, sensitivity: 'base' }) < 0) {
      minimumPlatformVersion = candidateVersion;
    }
  }

  return minimumPlatformVersion;
};

export const buildCatalogContractCompatibility = (
  versions: CatalogContractVersion[],
  options: CompatibilityOptions = {},
): CatalogContractCompatibility => {
  const latestCompatibleVersion = getLatestCompatibleVersion(versions, options);
  return {
    is_compatible: latestCompatibleVersion !== null,
    latest_compatible_version: latestCompatibleVersion,
    minimum_platform_version: getMinimumPlatformVersion(versions),
  };
};

const mapContractToVersion = (
  contract: Pick<BasicStoreEntityCatalogContract, 'contract_version' | 'support_version'>,
): CatalogContractVersion => ({
  version: contract.contract_version,
  support_version: contract.support_version ?? null,
  min_version: contract.support_version ?? null,
  min_platform_version: contract.support_version ?? null,
});

export const selectLatestContractsBySlug = (
  contracts: Array<BasicStoreEntityCatalogContract & SlugContract & ContractVersionContract>,
) => {
  return [...contracts]
    .sort(compareContractVersionDesc)
    .reduce<BasicStoreEntityCatalogContract[]>((acc, contract) => {
      if (acc.some((entry) => entry.slug === contract.slug)) {
        return acc;
      }
      acc.push(contract);
      return acc;
    }, []);
};

export const groupContractVersionsBySlug = (
  contracts: Array<BasicStoreEntityCatalogContract & SlugContract & ContractVersionContract>,
) => {
  const versionsBySlug = new Map<string, CatalogContractVersion[]>();
  for (const contract of [...contracts].sort(compareContractVersionDesc)) {
    const existingVersions = versionsBySlug.get(contract.slug) ?? [];
    if (existingVersions.some((version) => version.version === contract.contract_version)) {
      continue;
    }
    existingVersions.push(mapContractToVersion(contract));
    versionsBySlug.set(contract.slug, existingVersions);
  }
  return versionsBySlug;
};
