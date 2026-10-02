import { describe, expect, it, vi } from 'vitest';
import type { BasicStoreEntityCatalogContract } from '../../../../src/modules/catalog/catalog-types';
import {
  buildCatalogContractCompatibility,
  buildConnectorUpdateStatus,
  compareContractVersionDesc,
  compareContractVersions,
  filterAndSortLatestCompatibleContracts,
  getLatestCompatibleVersion,
  groupContractVersionsBySlug,
  isSupportVersionCompatible,
  parseCatalogSemver,
  selectLatestContractsBySlug,
} from '../../../../src/modules/catalog/catalog-version-utils';

const buildContract = (args: {
  contract_id: string;
  contract_version: string;
  support_version?: string;
  min_version?: string;
  max_version?: string;
  slug?: string;
}) => {
  return {
    contract_id: args.contract_id,
    contract_version: args.contract_version,
    support_version: args.support_version,
    min_version: args.min_version,
    max_version: args.max_version,
    slug: args.slug ?? args.contract_id,
  } as unknown as BasicStoreEntityCatalogContract;
};

describe('catalog-version-utils', () => {
  it('should coerce semantic versions from strings', () => {
    expect(parseCatalogSemver('>= 6.5.2')?.version).toBe('6.5.2');
    expect(parseCatalogSemver('7.2.0')?.version).toBe('7.2.0');
    expect(parseCatalogSemver(undefined)).toBeNull();
  });

  it('should evaluate support version ranges', () => {
    expect(isSupportVersionCompatible(
      buildContract({ contract_id: 'c1', contract_version: '1.0.0' }),
      { platformVersion: '7.2.0' },
    )).toBe(true);

    expect(isSupportVersionCompatible(
      buildContract({ contract_id: 'c2', contract_version: '1.0.0', support_version: '>= 7.1.0' }),
      { platformVersion: '7.2.0' },
    )).toBe(true);

    expect(isSupportVersionCompatible(
      buildContract({ contract_id: 'c3', contract_version: '1.0.0', support_version: '>= 8.0.0' }),
      { platformVersion: '7.2.0' },
    )).toBe(false);

    expect(isSupportVersionCompatible(
      buildContract({ contract_id: 'c4', contract_version: '1.0.0', support_version: '>= 7.1.0 < 7.3.0' }),
      { platformVersion: '7.2.0' },
    )).toBe(true);
    expect(isSupportVersionCompatible(
      buildContract({ contract_id: 'c5', contract_version: '1.0.0', support_version: '>= 7.1.0 < 7.2.0' }),
      { platformVersion: '7.2.0' },
    )).toBe(false);
  });

  it('should report unparsable support versions as incompatible', () => {
    const onUnparsableVersion = vi.fn();
    const isCompatible = isSupportVersionCompatible(
      buildContract({ contract_id: 'c4', contract_version: '1.0.0', support_version: 'not-a-version' }),
      { platformVersion: '7.2.0', onUnparsableVersion },
    );
    expect(isCompatible).toBe(false);
    expect(onUnparsableVersion).toHaveBeenCalledWith({
      contractId: 'c4',
      field: 'support_version',
      version: 'not-a-version',
      platformVersion: '7.2.0',
    });
  });

  it('should throw when the platform version cannot be parsed', () => {
    const onUnparsableVersion = vi.fn();
    expect(() => isSupportVersionCompatible(
      buildContract({ contract_id: 'c6', contract_version: '1.0.0', support_version: '>= 7.0.0' }),
      { platformVersion: 'not-a-version', onUnparsableVersion },
    )).toThrowError('Invalid platform version for catalog contract compatibility');
    expect(onUnparsableVersion).not.toHaveBeenCalled();
  });

  it('should evaluate inclusive minimum and maximum platform versions', () => {
    const contract = buildContract({
      contract_id: 'bounded',
      contract_version: '1.0.0',
      min_version: '7.0.0',
      max_version: '7.5.0',
    });

    expect(isSupportVersionCompatible(contract, { platformVersion: '7.0.0' })).toBe(true);
    expect(isSupportVersionCompatible(contract, { platformVersion: '7.5.0' })).toBe(true);
    expect(isSupportVersionCompatible(contract, { platformVersion: '6.9.9' })).toBe(false);
    expect(isSupportVersionCompatible(contract, { platformVersion: '7.5.1' })).toBe(false);
  });

  it('should reject non-semver min and max versions', () => {
    const onUnparsableVersion = vi.fn();
    expect(isSupportVersionCompatible(
      buildContract({ contract_id: 'invalid-min', contract_version: '1.0.0', min_version: '>= 7.0.0' }),
      { platformVersion: '7.2.0', onUnparsableVersion },
    )).toBe(false);
    expect(isSupportVersionCompatible(
      buildContract({ contract_id: 'invalid-max', contract_version: '1.0.0', max_version: 'latest' }),
      { platformVersion: '7.2.0', onUnparsableVersion },
    )).toBe(false);
    expect(onUnparsableVersion).toHaveBeenNthCalledWith(1, {
      contractId: 'invalid-min',
      field: 'min_version',
      version: '>= 7.0.0',
      platformVersion: '7.2.0',
    });
    expect(onUnparsableVersion).toHaveBeenNthCalledWith(2, {
      contractId: 'invalid-max',
      field: 'max_version',
      version: 'latest',
      platformVersion: '7.2.0',
    });
  });

  it('should compare contract versions in descending semantic order', () => {
    const contracts = [
      buildContract({ contract_id: 'c1', contract_version: '1.2.0' }),
      buildContract({ contract_id: 'c2', contract_version: '2.0.0' }),
      buildContract({ contract_id: 'c3', contract_version: '1.10.0' }),
    ];
    const sorted = contracts.sort(compareContractVersionDesc);
    expect(sorted.map((contract) => contract.contract_id)).toEqual(['c2', 'c3', 'c1']);
  });

  it('should treat rolling as newer than semantic versions', () => {
    expect(compareContractVersions('rolling', '2.0.0')).toBeGreaterThan(0);
    expect(compareContractVersions('2.0.0', 'rolling')).toBeLessThan(0);
    expect(compareContractVersions('rolling', 'rolling')).toBe(0);

    const contracts = [
      buildContract({ contract_id: 'semantic', contract_version: '2.0.0' }),
      buildContract({ contract_id: 'rolling', contract_version: 'rolling' }),
    ];
    expect(contracts.sort(compareContractVersionDesc).map((contract) => contract.contract_id)).toEqual([
      'rolling',
      'semantic',
    ]);
  });

  it('should filter incompatible contracts and keep latest versions first', () => {
    const onUnparsableVersion = vi.fn();
    const contracts = [
      buildContract({ contract_id: 'latest-compatible', contract_version: '2.0.0', support_version: '>= 7.0.0' }),
      buildContract({ contract_id: 'older-compatible', contract_version: '1.5.0', support_version: '>= 6.5.2' }),
      buildContract({ contract_id: 'no-support-version', contract_version: '1.0.0' }),
      buildContract({ contract_id: 'too-new', contract_version: '3.0.0', support_version: '8.0.0' }),
      buildContract({ contract_id: 'invalid-support-version', contract_version: '2.5.0', support_version: 'broken-version' }),
      buildContract({ contract_id: 'too-old', contract_version: '2.6.0', min_version: '7.5.0', max_version: '8.0.0' }),
      buildContract({ contract_id: 'bounded-compatible', contract_version: '2.7.0', min_version: '7.1.0', max_version: '7.5.0' }),
      buildContract({ contract_id: 'too-old-upper-bound', contract_version: '2.8.0', max_version: '7.1.0' }),
    ];

    const filtered = filterAndSortLatestCompatibleContracts(contracts, {
      platformVersion: '7.2.0',
      onUnparsableVersion,
    });

    expect(filtered.map((contract) => contract.contract_id)).toEqual([
      'bounded-compatible',
      'latest-compatible',
      'older-compatible',
      'no-support-version',
    ]);
    expect(onUnparsableVersion).toHaveBeenCalledTimes(1);
  });

  it('should select the latest compatible contract version per slug', () => {
    const selected = selectLatestContractsBySlug([
      buildContract({ contract_id: 'compatible-1', slug: 'same-slug', contract_version: '1.0.0', min_version: '7.0.0' }),
      buildContract({ contract_id: 'compatible-1.5', slug: 'same-slug', contract_version: '1.5.0', min_version: '7.1.0' }),
      buildContract({ contract_id: 'incompatible-2', slug: 'same-slug', contract_version: '2.0.0', min_version: '9999.0.0' }),
      buildContract({ contract_id: 'other-1', slug: 'other-slug', contract_version: '1.0.0', min_version: '7.0.0' }),
    ], { platformVersion: '7.2.0' });

    expect(selected.map((contract) => contract.contract_id)).toEqual(['compatible-1.5', 'other-1']);
  });

  it('should keep the latest contract version per slug when no version is compatible', () => {
    const selected = selectLatestContractsBySlug([
      buildContract({ contract_id: 'incompatible-1', slug: 'same-slug', contract_version: '1.0.0', min_version: '9000.0.0' }),
      buildContract({ contract_id: 'incompatible-2', slug: 'same-slug', contract_version: '2.0.0', min_version: '9999.0.0' }),
    ], { platformVersion: '7.2.0' });

    expect(selected.map((contract) => contract.contract_id)).toEqual(['incompatible-2']);
  });

  it('should select the same contract as the deployment for every slug', () => {
    const contracts = [
      buildContract({ contract_id: 'compatible-1', slug: 'same-slug', contract_version: '1.0.0', min_version: '7.0.0' }),
      buildContract({ contract_id: 'compatible-1.5', slug: 'same-slug', contract_version: '1.5.0', min_version: '7.1.0', max_version: '7.5.0' }),
      buildContract({ contract_id: 'incompatible-rolling', slug: 'same-slug', contract_version: 'rolling', min_version: '9999.0.0' }),
    ];
    const options = { platformVersion: '7.2.0' };

    const [selected] = selectLatestContractsBySlug(contracts, options);
    const [deployed] = filterAndSortLatestCompatibleContracts(contracts, options);

    expect(selected.contract_id).toBe('compatible-1.5');
    expect(selected.contract_id).toBe(deployed.contract_id);
  });

  it('should group versions by slug in descending version order', () => {
    const grouped = groupContractVersionsBySlug([
      buildContract({ contract_id: 'compatible-1', slug: 'same-slug', contract_version: '1.0.0', min_version: '7.0.0', max_version: '7.5.0' }),
      buildContract({ contract_id: 'incompatible-2', slug: 'same-slug', contract_version: '2.0.0', min_version: '9999.0.0' }),
      buildContract({ contract_id: 'other-1', slug: 'other-slug', contract_version: '1.0.0', support_version: '>= 7.1.0' }),
    ]);

    expect(grouped.get('same-slug')).toEqual([
      { version: '2.0.0', support_version: null, min_version: '9999.0.0', max_version: null },
      { version: '1.0.0', support_version: null, min_version: '7.0.0', max_version: '7.5.0' },
    ]);
    expect(grouped.get('other-slug')).toEqual([
      { version: '1.0.0', support_version: '>= 7.1.0', min_version: null, max_version: null },
    ]);
  });

  it('should compute compatibility with the same check as the contracts selection', () => {
    const versions = [
      { version: '2.0.0', min_version: '9999.0.0' },
      { version: '1.0.0', min_version: '7.0.0', max_version: '8.0.0' },
    ];

    expect(getLatestCompatibleVersion(versions, { platformVersion: '7.2.0' })).toBe('1.0.0');
    expect(buildCatalogContractCompatibility(versions, { platformVersion: '7.2.0' })).toEqual({
      is_compatible: true,
      latest_compatible_version: '1.0.0',
      minimum_platform_version: null,
      maximum_platform_version: null,
    });
  });

  it('should give the lowest platform version to upgrade to when the platform is too old', () => {
    const versions = [
      { version: '2.0.0', min_version: '7.5.0' },
      { version: '1.0.0', min_version: '7.3.0', max_version: '7.4.0' },
    ];

    expect(buildCatalogContractCompatibility(versions, { platformVersion: '7.2.0' })).toEqual({
      is_compatible: false,
      latest_compatible_version: null,
      minimum_platform_version: '7.3.0',
      maximum_platform_version: null,
    });
  });

  it('should not suggest a min_version that is not valid semver', () => {
    const versions = [
      { version: '2.0.0', min_version: '7.260950' },
      { version: '1.0.0', min_version: '7.261000.0' },
    ];

    expect(buildCatalogContractCompatibility(versions, { platformVersion: '7.260930.0', onUnparsableVersion: () => {} })).toEqual({
      is_compatible: false,
      latest_compatible_version: null,
      minimum_platform_version: '7.261000.0',
      maximum_platform_version: null,
    });
  });

  it('should give the highest supported platform version when the platform is too new', () => {
    const versions = [
      { version: '2.0.0', min_version: '7.0.0', max_version: '7.1.0' },
      { version: '1.0.0', max_version: '6.9.0' },
    ];

    expect(buildCatalogContractCompatibility(versions, { platformVersion: '7.2.0' })).toEqual({
      is_compatible: false,
      latest_compatible_version: null,
      minimum_platform_version: null,
      maximum_platform_version: '7.1.0',
    });
  });

  it('should not suggest a platform version when the platform is between two supported ranges', () => {
    const versions = [
      { version: '2.0.0', min_version: '7.3.0' },
      { version: '1.0.0', min_version: '7.0.0', max_version: '7.1.0' },
    ];

    expect(buildCatalogContractCompatibility(versions, { platformVersion: '7.2.0' })).toEqual({
      is_compatible: false,
      latest_compatible_version: null,
      minimum_platform_version: null,
      maximum_platform_version: null,
    });
  });

  it('should compute compatibility from V0 support version ranges', () => {
    expect(buildCatalogContractCompatibility([{ version: 'rolling', support_version: '>=6.8.0' }], { platformVersion: '7.2.0' })).toEqual({
      is_compatible: true,
      latest_compatible_version: 'rolling',
      minimum_platform_version: null,
      maximum_platform_version: null,
    });
    expect(buildCatalogContractCompatibility([{ version: 'rolling', support_version: '>= 7.5.0' }], { platformVersion: '7.2.0' })).toEqual({
      is_compatible: false,
      latest_compatible_version: null,
      minimum_platform_version: null,
      maximum_platform_version: null,
    });
  });

  it('should name the selected contract as the latest compatible version, including rolling', () => {
    const contracts = [
      buildContract({ contract_id: 'compatible-1', slug: 'same-slug', contract_version: '1.0.0', min_version: '7.0.0' }),
      buildContract({ contract_id: 'rolling', slug: 'same-slug', contract_version: 'rolling', min_version: '7.0.0' }),
    ];
    const options = { platformVersion: '7.2.0' };
    const [selected] = selectLatestContractsBySlug(contracts, options);
    const versions = groupContractVersionsBySlug(contracts).get('same-slug') ?? [];

    expect(getLatestCompatibleVersion(versions, options)).toBe(selected.contract_version);
    expect(getLatestCompatibleVersion(versions, options)).toBe('rolling');
  });

  it('should expose connector update information from compatible and incompatible contract versions', () => {
    const status = buildConnectorUpdateStatus('1.0.0', [
      { version: '2.0.0', min_version: '9999.0.0' },
      { version: '1.5.0', min_version: '7.0.0' },
      { version: '1.0.0', min_version: '7.0.0' },
    ], { platformVersion: '7.2.0' });

    expect(status).toEqual({
      update_available: true,
      latest_compatible_version: '1.5.0',
      has_newer_incompatible_version: true,
    });
  });

  it('should compare connector versions like the auto-upgrade does', () => {
    const options = { platformVersion: '7.2.0' };

    expect(buildConnectorUpdateStatus('1.0.0', [{ version: 'rolling' }, { version: '1.0.0' }], options)).toEqual({
      update_available: true,
      latest_compatible_version: 'rolling',
      has_newer_incompatible_version: false,
    });
    expect(buildConnectorUpdateStatus('rolling', [{ version: 'rolling' }, { version: '2.0.0' }], options).update_available).toBe(false);
    expect(buildConnectorUpdateStatus(null, [{ version: '2.0.0' }], options).update_available).toBe(false);
  });
});
