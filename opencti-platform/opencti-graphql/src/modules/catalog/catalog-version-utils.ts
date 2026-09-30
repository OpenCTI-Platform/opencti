import semver from 'semver';
import validRange from 'semver/ranges/valid.js';
import { UnsupportedError } from '../../config/errors';
import { logApp, PLATFORM_VERSION } from '../../config/conf';
import type { BasicStoreEntityCatalogContract } from './catalog-types';

type SupportVersionContract = Pick<BasicStoreEntityCatalogContract, 'support_version' | 'min_version' | 'max_version' | 'contract_id'>;
type ContractVersionContract = Pick<BasicStoreEntityCatalogContract, 'contract_version'>;

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
