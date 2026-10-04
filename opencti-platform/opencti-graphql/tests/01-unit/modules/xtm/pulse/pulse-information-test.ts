import { describe, expect, it } from 'vitest';
import {
  buildPulseDocument,
  buildPulsePreviewDocument,
  pulsePrevalenceRank,
  combinePulseLookups,
  combinePulsePreviewSignals,
  PULSE_PREVIEW_CLEARED_DOCUMENT,
  toPulseInformationOutput,
} from '../../../../../src/modules/xtm/pulse/pulse-information';
import {
  getPulseAccess,
  hasPulseReadAccess,
  matchRegionBucket,
  matchSectorBucket,
  readPulseSettings,
  isPulseContributing,
} from '../../../../../src/modules/xtm/pulse/pulse-settings';
import { PULSE_SCOPE_ENTITY_TYPES, type BasicStorePulseEntity, type PulseHubLookupResult } from '../../../../../src/modules/xtm/pulse/pulse-types';
import { PulseAccess, PulseMode, PulsePrevalence, PulseRegionBucket, PulseSectorBucket, PulseTrend } from '../../../../../src/generated/graphql';
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

describe('Threat Pulse preview information', () => {
  it('should keep the most prevalent signal of an object with several keys in the digest', () => {
    expect(combinePulsePreviewSignals([
      { prevalence: PulsePrevalence.Uncommon, trend: PulseTrend.Falling },
      { prevalence: PulsePrevalence.Widespread, trend: PulseTrend.Rising },
    ])).toEqual({ prevalence: PulsePrevalence.Widespread, trend: PulseTrend.Rising });
    expect(combinePulsePreviewSignals([])).toBeNull();
  });

  it('should rank the prevalence from 0 below the anonymity threshold to 4 for widespread', () => {
    expect([
      pulsePrevalenceRank(false, PulsePrevalence.Rare),
      pulsePrevalenceRank(true, PulsePrevalence.Rare),
      pulsePrevalenceRank(true, PulsePrevalence.Uncommon),
      pulsePrevalenceRank(true, PulsePrevalence.Common),
      pulsePrevalenceRank(true, PulsePrevalence.Widespread),
    ]).toEqual([0, 1, 2, 3, 4]);
  });

  it('should write the coarse signal only, marked as preview', () => {
    const updatedAt = new Date('2026-10-03T10:00:00.000Z');
    const doc = buildPulsePreviewDocument(['k1'], { prevalence: PulsePrevalence.Common, trend: PulseTrend.Rising }, updatedAt);
    expect(doc).toEqual({
      pulse_keys: ['k1'],
      pulse_prevalence: PulsePrevalence.Common,
      pulse_trend: PulseTrend.Rising,
      pulse_sector_trend: null,
      pulse_first_seen_network: null,
      pulse_community_uniqueness: null,
      // The sort key of the prevalence is the same in preview and full mode
      pulse_prevalence_rank: 3,
      pulse_information: { published: true, preview: true, updated_at: updatedAt.toISOString() },
    });
    const output = toPulseInformationOutput({ entity_type: 'Indicator', ...doc } as unknown as BasicStorePulseEntity);
    expect(output).toMatchObject({
      published: true,
      preview: true,
      prevalence: PulsePrevalence.Common,
      trend: PulseTrend.Rising,
      platforms_bucket: null,
      first_seen_network: null,
      trend_series: [],
      sector_trend: null,
      community_uniqueness: null,
    });
  });

  it('should clear the signal of an object that left the digest but keep its keys', () => {
    expect(Object.keys(PULSE_PREVIEW_CLEARED_DOCUMENT)).not.toContain('pulse_keys');
    expect(Object.values(PULSE_PREVIEW_CLEARED_DOCUMENT).every((value) => value === null)).toBe(true);
  });
});

describe('Threat Pulse settings', () => {
  it('should run the preview by default, contributing nothing, with every type in scope', () => {
    const values = readPulseSettings({ id: 'settings' } as BasicStoreSettings);
    expect(values.mode).toBe(PulseMode.Preview);
    expect(values.scopes).toEqual(PULSE_SCOPE_ENTITY_TYPES);
    expect(isPulseContributing(values)).toBe(false);
  });

  it('should read the contribute-only mode of the first builds as the contribution', () => {
    const legacy = readPulseSettings({ id: 'settings', pulse_mode: 'contribute' } as unknown as BasicStoreSettings);
    expect(legacy.mode).toBe(PulseMode.ContributeAndRead);
    expect(isPulseContributing(legacy)).toBe(true);
  });

  it.each([
    { mode: 'preview', registered: true, readAccess: false, access: PulseAccess.Preview },
    { mode: 'contribute_and_read', registered: true, readAccess: true, access: PulseAccess.Full },
    // Opted in, but no contribution accepted yet, or none within the grace period
    { mode: 'contribute_and_read', registered: true, readAccess: false, access: PulseAccess.Preview },
    { mode: 'off', registered: true, readAccess: false, access: PulseAccess.Off },
    { mode: 'contribute_and_read', registered: false, readAccess: true, access: PulseAccess.NotConnected },
    { mode: 'preview', registered: false, readAccess: false, access: PulseAccess.NotConnected },
  ])('should give $access to $mode (registered $registered, read access $readAccess)', ({ mode, registered, readAccess, access }) => {
    const values = readPulseSettings({ id: 'settings', pulse_mode: mode } as unknown as BasicStoreSettings);
    expect(getPulseAccess(values, registered, readAccess)).toBe(access);
  });

  it.each([
    { state: {}, readAccess: false },
    { state: { contribution_accepted: 'true' }, readAccess: true },
    { state: { contribution_accepted: 'true', contribution_lapsed: 'true' }, readAccess: false },
    { state: { contribution_lapsed: 'true' }, readAccess: false },
  ])('should open the full reads only after an accepted contribution ($state)', ({ state, readAccess }) => {
    expect(hasPulseReadAccess(state)).toBe(readAccess);
  });

  it('should ignore unknown values', () => {
    const values = readPulseSettings({
      id: 'settings',
      pulse_mode: 'read_only',
      pulse_scopes: ['Indicator', 'Report'],
      pulse_sector_bucket: 'acme-bank',
      pulse_region_bucket: 'paris',
    } as unknown as BasicStoreSettings);
    expect(values.mode).toBe(PulseMode.Preview);
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
