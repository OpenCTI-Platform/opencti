import { describe, expect, it, vi } from 'vitest';
import type { BasicStoreEntityCatalogContract } from '../../../../src/modules/catalog/catalog-types';
import {
  buildCatalogContractCompatibility,
  compareContractVersionDesc,
  filterAndSortLatestCompatibleContracts,
  getLatestCompatibleVersion,
  getMinimumPlatformVersion,
  groupContractVersionsBySlug,
  isSupportVersionCompatible,
  parseCatalogSemver,
  selectLatestContractsBySlug,
} from '../../../../src/modules/catalog/catalog-version-utils';

const buildContract = (args: {
  contract_id: string;
  contract_version: string;
  support_version?: string;
  slug?: string;
}) => {
  return {
    contract_id: args.contract_id,
    contract_version: args.contract_version,
    support_version: args.support_version,
    slug: args.slug ?? args.contract_id,
  } as unknown as BasicStoreEntityCatalogContract;
};

describe('catalog-version-utils', () => {
  it('should coerce semantic versions from strings', () => {
    expect(parseCatalogSemver('>= 6.5.2')?.version).toBe('6.5.2');
    expect(parseCatalogSemver('7.2.0')?.version).toBe('7.2.0');
    expect(parseCatalogSemver(undefined)).toBeNull();
  });

  it('should evaluate support version compatibility', () => {
    expect(isSupportVersionCompatible(
      buildContract({ contract_id: 'c1', contract_version: '1.0.0' }),
      { platformVersion: '7.2.0' },
    )).toBe(true);

    expect(isSupportVersionCompatible(
      buildContract({ contract_id: 'c2', contract_version: '1.0.0', support_version: '7.1.0' }),
      { platformVersion: '7.2.0' },
    )).toBe(true);

    expect(isSupportVersionCompatible(
      buildContract({ contract_id: 'c3', contract_version: '1.0.0', support_version: '8.0.0' }),
      { platformVersion: '7.2.0' },
    )).toBe(false);
  });

  it('should report unparsable support versions as incompatible', () => {
    const onUnparsableSupportVersion = vi.fn();
    const isCompatible = isSupportVersionCompatible(
      buildContract({ contract_id: 'c4', contract_version: '1.0.0', support_version: 'not-a-version' }),
      { platformVersion: '7.2.0', onUnparsableSupportVersion },
    );
    expect(isCompatible).toBe(false);
    expect(onUnparsableSupportVersion).toHaveBeenCalledWith({
      contractId: 'c4',
      supportVersion: 'not-a-version',
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

  it('should filter incompatible contracts and keep latest versions first', () => {
    const onUnparsableSupportVersion = vi.fn();
    const contracts = [
      buildContract({ contract_id: 'latest-compatible', contract_version: '2.0.0', support_version: '7.0.0' }),
      buildContract({ contract_id: 'older-compatible', contract_version: '1.5.0', support_version: '>= 6.5.2' }),
      buildContract({ contract_id: 'no-support-version', contract_version: '1.0.0' }),
      buildContract({ contract_id: 'too-new', contract_version: '3.0.0', support_version: '8.0.0' }),
      buildContract({ contract_id: 'invalid-support-version', contract_version: '2.5.0', support_version: 'broken-version' }),
    ];

    const filtered = filterAndSortLatestCompatibleContracts(contracts, {
      platformVersion: '7.2.0',
      onUnparsableSupportVersion,
    });

    expect(filtered.map((contract) => contract.contract_id)).toEqual([
      'latest-compatible',
      'older-compatible',
      'no-support-version',
    ]);
    expect(onUnparsableSupportVersion).toHaveBeenCalledTimes(1);
  });

  it('should keep the latest contract version per slug even when it is incompatible', () => {
    const selected = selectLatestContractsBySlug([
      buildContract({ contract_id: 'compatible-1', slug: 'same-slug', contract_version: '1.0.0', support_version: '7.0.0' }),
      buildContract({ contract_id: 'incompatible-2', slug: 'same-slug', contract_version: '2.0.0', support_version: '9999.0.0' }),
      buildContract({ contract_id: 'other-1', slug: 'other-slug', contract_version: '1.0.0', support_version: '7.0.0' }),
    ]);

    expect(selected.map((contract) => contract.contract_id)).toEqual(['incompatible-2', 'other-1']);
  });

  it('should group versions by slug in descending version order', () => {
    const grouped = groupContractVersionsBySlug([
      buildContract({ contract_id: 'compatible-1', slug: 'same-slug', contract_version: '1.0.0', support_version: '7.0.0' }),
      buildContract({ contract_id: 'incompatible-2', slug: 'same-slug', contract_version: '2.0.0', support_version: '9999.0.0' }),
      buildContract({ contract_id: 'other-1', slug: 'other-slug', contract_version: '1.0.0', support_version: '7.1.0' }),
    ]);

    expect(grouped.get('same-slug')).toEqual([
      { version: '2.0.0', support_version: '9999.0.0', min_version: '9999.0.0', min_platform_version: '9999.0.0' },
      { version: '1.0.0', support_version: '7.0.0', min_version: '7.0.0', min_platform_version: '7.0.0' },
    ]);
    expect(grouped.get('other-slug')).toEqual([
      { version: '1.0.0', support_version: '7.1.0', min_version: '7.1.0', min_platform_version: '7.1.0' },
    ]);
  });

  it('should compute compatibility from contract versions for the current platform', () => {
    const versions = [
      { version: '2.0.0', support_version: '9999.0.0', min_version: '9999.0.0', min_platform_version: '9999.0.0' },
      { version: '1.0.0', support_version: '7.0.0', min_version: '7.0.0', min_platform_version: '7.0.0' },
    ];

    expect(getLatestCompatibleVersion(versions, { platformVersion: '7.2.0' })).toBe('1.0.0');
    expect(getMinimumPlatformVersion(versions)).toBe('7.0.0');
    expect(buildCatalogContractCompatibility(versions, { platformVersion: '7.2.0' })).toEqual({
      is_compatible: true,
      latest_compatible_version: '1.0.0',
      minimum_platform_version: '7.0.0',
    });
  });
});

