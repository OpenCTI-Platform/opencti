import { describe, expect, it } from 'vitest';
import { buildPulseDocument, combinePulseLookups, toPulseInformationOutput } from '../../../../../src/modules/xtm/pulse/pulse-information';
import { matchRegionBucket, matchSectorBucket, readPulseSettings, isPulseContributing, isPulseReading } from '../../../../../src/modules/xtm/pulse/pulse-settings';
import { PULSE_SCOPE_ENTITY_TYPES, type BasicStorePulseEntity, type PulseHubLookupResult } from '../../../../../src/modules/xtm/pulse/pulse-types';
import { PulseMode, PulsePrevalence, PulseRegionBucket, PulseSectorBucket, PulseTrend } from '../../../../../src/generated/graphql';
import type { BasicStoreSettings } from '../../../../../src/types/settings';

const unpublished = (hash: string): PulseHubLookupResult => ({
  hash,
  published: false,
  prevalence_bucket: null,
  platforms_bucket: null,
  first_seen_network: null,
  last_seen_network: null,
  trend: null,
  trend_series: null,
  sector_trend: null,
  sector_platforms_bucket: null,
});

const published = (hash: string, overrides: Partial<PulseHubLookupResult>): PulseHubLookupResult => ({
  hash,
  published: true,
  prevalence_bucket: PulsePrevalence.Uncommon,
  platforms_bucket: '5-9',
  first_seen_network: '2026-09-01',
  last_seen_network: '2026-10-02',
  trend: PulseTrend.Stable,
  trend_series: [0, 0, 5, 6],
  sector_trend: null,
  sector_platforms_bucket: null,
  ...overrides,
});

describe('Threat Pulse network information', () => {
  it('should mark objects below the anonymity threshold as rare and unique', () => {
    const information = combinePulseLookups([unpublished('a'), unpublished('b')]);
    expect(information).toMatchObject({ published: false, prevalence: PulsePrevalence.Rare, communityUniqueness: 100, trend: null, firstSeenNetwork: null });
  });

  it('should take the most prevalent key of an object with aliases', () => {
    const information = combinePulseLookups([
      published('alias', { platforms_bucket: '5-9', first_seen_network: '2026-08-01', trend: PulseTrend.Falling }),
      published('name', { platforms_bucket: '25-49', prevalence_bucket: PulsePrevalence.Common, first_seen_network: '2026-09-15', last_seen_network: '2026-10-03', trend: PulseTrend.Rising }),
      unpublished('other'),
    ]);
    expect(information).toMatchObject({
      published: true,
      prevalence: PulsePrevalence.Common,
      platformsBucket: '25-49',
      firstSeenNetwork: '2026-08-01',
      lastSeenNetwork: '2026-10-03',
      trend: PulseTrend.Rising,
      communityUniqueness: 25,
    });
  });

  it('should keep the sector trend when the sector is above the threshold', () => {
    const information = combinePulseLookups([published('a', { sector_trend: PulseTrend.Rising, sector_platforms_bucket: '5-9' })]);
    expect(information.sectorTrend).toBe(PulseTrend.Rising);
    expect(information.sectorPlatformsBucket).toBe('5-9');
  });

  it('should build the stored document and expose it back', () => {
    const updatedAt = new Date('2026-10-03T02:00:00.000Z');
    const keys = ['00112233445566778899aabbccddeeff'];
    const doc = buildPulseDocument(keys, combinePulseLookups([published('a', { sector_trend: PulseTrend.Rising, sector_platforms_bucket: '10-24' })]), updatedAt);
    expect(doc).toMatchObject({
      pulse_keys: keys,
      pulse_prevalence: PulsePrevalence.Uncommon,
      pulse_trend: PulseTrend.Stable,
      pulse_sector_trend: PulseTrend.Rising,
      pulse_first_seen_network: '2026-09-01T00:00:00.000Z',
      pulse_community_uniqueness: 50,
    });
    const output = toPulseInformationOutput({ entity_type: 'Indicator', ...doc } as unknown as BasicStorePulseEntity);
    expect(output).toMatchObject({
      published: true,
      prevalence: PulsePrevalence.Uncommon,
      platforms_bucket: '5-9',
      last_seen_network: '2026-10-02T00:00:00.000Z',
      trend_series: [0, 0, 5, 6],
      sector_platforms_bucket: '10-24',
      updated_at: updatedAt.toISOString(),
    });
  });

  it('should expose nothing for an entity never looked up', () => {
    expect(toPulseInformationOutput({ entity_type: 'Indicator' } as BasicStorePulseEntity)).toBeNull();
  });
});

describe('Threat Pulse settings', () => {
  it('should be off by default with every type in scope', () => {
    const values = readPulseSettings({ id: 'settings' } as BasicStoreSettings);
    expect(values.mode).toBe(PulseMode.Off);
    expect(values.scopes).toEqual(PULSE_SCOPE_ENTITY_TYPES);
    expect(isPulseContributing(values)).toBe(false);
    expect(isPulseReading(values)).toBe(false);
  });

  it('should require contributing to read', () => {
    const contribute = readPulseSettings({ id: 'settings', pulse_mode: 'contribute' } as unknown as BasicStoreSettings);
    expect(isPulseContributing(contribute)).toBe(true);
    expect(isPulseReading(contribute)).toBe(false);
    const read = readPulseSettings({ id: 'settings', pulse_mode: 'contribute_and_read' } as unknown as BasicStoreSettings);
    expect(isPulseReading(read)).toBe(true);
  });

  it('should ignore unknown values', () => {
    const values = readPulseSettings({
      id: 'settings',
      pulse_mode: 'read_only',
      pulse_scopes: ['Indicator', 'Report'],
      pulse_sector_bucket: 'acme-bank',
      pulse_region_bucket: 'paris',
    } as unknown as BasicStoreSettings);
    expect(values.mode).toBe(PulseMode.Off);
    expect(values.scopes).toEqual(['Indicator']);
    expect(values.sectorBucket).toBeUndefined();
    expect(values.regionBucket).toBeUndefined();
  });

  it('should suggest coarse buckets from the organization sectors and regions', () => {
    expect(matchSectorBucket(['Banking and finance'])).toBe(PulseSectorBucket.Finance);
    expect(matchSectorBucket(['Hospitals'])).toBe(PulseSectorBucket.Healthcare);
    expect(matchSectorBucket(['Something else'])).toBeUndefined();
    expect(matchRegionBucket(['Western Europe'])).toBe(PulseRegionBucket.Europe);
    expect(matchRegionBucket(['Western Asia'])).toBe(PulseRegionBucket.MiddleEast);
    expect(matchRegionBucket(['Northern America'])).toBe(PulseRegionBucket.NorthAmerica);
    expect(matchRegionBucket(['South America'])).toBe(PulseRegionBucket.LatinAmerica);
  });
});
