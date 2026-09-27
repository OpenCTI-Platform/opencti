import semver from 'semver';
import { logApp, PLATFORM_VERSION } from '../../config/conf';
import type { BasicStoreEntityCatalogContract } from './catalog-types';

type SupportVersionContract = Pick<BasicStoreEntityCatalogContract, 'support_version' | 'contract_id'>;
type ContractVersionContract = Pick<BasicStoreEntityCatalogContract, 'contract_version'>;

type CompatibilityOptions = {
  platformVersion?: string;
  onUnparsableSupportVersion?: (args: { contractId: string; supportVersion: string; platformVersion: string }) => void;
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
