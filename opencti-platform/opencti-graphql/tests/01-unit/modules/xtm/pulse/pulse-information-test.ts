import { describe, expect, it } from 'vitest';
import {
  buildPulseDocument,
  buildPulsePreviewDocument,
  pulsePrevalenceRank,
  combinePulseLookups,
  combinePulsePreviewSignals,
  PULSE_PREVIEW_CLEARED_DOCUMENT,
  type PulseFieldPolicy,
  pulseQueryClause,
  pulseRankSort,
  toPulseInformationOutput,
  visiblePulseInformation,
} from '../../../../../src/modules/xtm/pulse/pulse-information';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../../../src/schema/stixRefRelationship';
import { buildRefRelationSearchKey } from '../../../../../src/schema/general';
import {
  getPulseAccess,
  hasPulseReadAccess,
  matchRegionBucket,
  matchSectorBucket,
  readPulseSettings,
  isPulseConsentCurrent,
  isPulseContributing,
} from '../../../../../src/modules/xtm/pulse/pulse-settings';
import { PULSE_CONSENT_VERSION, PULSE_SCOPE_ENTITY_TYPES, type BasicStorePulseEntity, type PulseHubLookupResult } from '../../../../../src/modules/xtm/pulse/pulse-types';
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
  it('should give objects below the anonymity threshold no prevalence and the uniqueness published objects never reach', () => {
    const information = combinePulseLookups([unpublished('a'), unpublished('b')]);
    expect(information).toMatchObject({ published: false, prevalence: null, communityUniqueness: 100, trend: null, firstSeenNetwork: null });
    const document = buildPulseDocument(['a'], information, new Date('2026-10-03T00:00:00.000Z'));
    expect(document).toMatchObject({ pulse_prevalence: null, pulse_prevalence_rank: 0, pulse_trend: null, pulse_community_uniqueness: 100 });
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

describe('Threat Pulse information under the current access', () => {
  const updatedAt = new Date('2026-10-03T02:00:00.000Z');
  const fullDocument = buildPulseDocument(['k1'], combinePulseLookups([published('a', { sector_trend: PulseTrend.Rising, sector_platforms_bucket: '10-24' })]), updatedAt);
  const previewDocument = buildPulsePreviewDocument(['k1'], { prevalence: PulsePrevalence.Common, trend: PulseTrend.Rising }, updatedAt);
  const entity = (doc: Record<string, unknown>, overrides: Record<string, unknown> = {}) => (
    { entity_type: 'Malware', ...doc, ...overrides } as unknown as BasicStorePulseEntity
  );
  const markingPolicy = { knownMarkingIds: new Set(['tlp-green', 'tlp-red']), excludedMarkingIds: new Set(['tlp-red']) };
  const scopes = ['Malware', 'Indicator'];
  const preview: PulseFieldPolicy = { access: PulseAccess.Preview, scopes, markingPolicy: null };
  const full: PulseFieldPolicy = { access: PulseAccess.Full, scopes, markingPolicy };

  it('should show only the preview signal while the platform reads the preview, whatever a failed cleanup left', () => {
    expect(visiblePulseInformation(entity(fullDocument), preview)).toBeNull();
    expect(visiblePulseInformation(entity(previewDocument), preview)).toMatchObject({ preview: true, prevalence: PulsePrevalence.Common, platforms_bucket: null });
  });

  it('should show the full information of a contributable object in the full experience', () => {
    expect(visiblePulseInformation(entity(fullDocument, { [RELATION_OBJECT_MARKING]: ['tlp-green'] }), full)).toMatchObject({
      preview: false,
      platforms_bucket: '5-9',
      sector_trend: PulseTrend.Rising,
    });
  });

  it('should show nothing for an object excluded from the contribution in the full experience', () => {
    expect(visiblePulseInformation(entity(fullDocument, { [RELATION_OBJECT_MARKING]: ['tlp-red'] }), full)).toBeNull();
    expect(visiblePulseInformation(entity(fullDocument, { [RELATION_OBJECT_MARKING]: ['unknown-marking'] }), full)).toBeNull();
    expect(visiblePulseInformation(entity(fullDocument, { restricted_members: [{ id: 'user' }] }), full)).toBeNull();
  });

  it('should show nothing for a type out of scope, or once Threat Pulse is off or not connected', () => {
    expect(visiblePulseInformation(entity(previewDocument, { entity_type: 'Tool' }), preview)).toBeNull();
    expect(visiblePulseInformation(entity(fullDocument, { entity_type: 'Tool' }), full)).toBeNull();
    expect(visiblePulseInformation(entity(previewDocument), { access: PulseAccess.Off, scopes, markingPolicy: null })).toBeNull();
    expect(visiblePulseInformation(entity(fullDocument), { access: PulseAccess.NotConnected, scopes, markingPolicy })).toBeNull();
  });

  // The query clause of the generic filters, aggregations and date histograms, evaluated on the stored documents.
  const indexed: Record<string, (doc: Record<string, any>) => unknown> = {
    'entity_type.keyword': (doc) => doc.entity_type,
    'restricted_members.id': (doc) => (doc.restricted_members ?? []).map((member: { id: string }) => member.id),
    [buildRefRelationSearchKey(RELATION_GRANTED_TO)]: (doc) => doc[RELATION_GRANTED_TO],
    [buildRefRelationSearchKey(RELATION_OBJECT_MARKING)]: (doc) => doc[RELATION_OBJECT_MARKING],
  };
  const valuesOf = (doc: Record<string, any>, field: string): unknown[] => {
    const value = indexed[field] ? indexed[field](doc) : doc[field];
    if (value === null || value === undefined) return [];
    return Array.isArray(value) ? value : [value];
  };
  const matches = (clause: Record<string, any>, doc: Record<string, any>): boolean => {
    if (clause.match_none) return false;
    if (clause.terms) {
      const [[field, values]] = Object.entries(clause.terms) as [string, unknown[]][];
      return valuesOf(doc, field).some((value) => values.includes(value));
    }
    if (clause.exists) return valuesOf(doc, clause.exists.field).length > 0;
    if (clause.nested) return matches(clause.nested.query, doc);
    if (clause.bool) {
      const { filter = [], must_not: mustNot = [] } = clause.bool;
      return filter.every((sub: Record<string, any>) => matches(sub, doc)) && !mustNot.some((sub: Record<string, any>) => matches(sub, doc));
    }
    throw new Error(`Unexpected clause ${JSON.stringify(clause)}`);
  };

  it('should let a generic query use the stored values of exactly the objects whose information is shown', () => {
    const documents = [
      entity(fullDocument),
      entity(previewDocument),
      entity(fullDocument, { [RELATION_OBJECT_MARKING]: ['tlp-green'] }),
      entity(fullDocument, { [RELATION_OBJECT_MARKING]: ['tlp-green', 'tlp-red'] }),
      entity(previewDocument, { [RELATION_OBJECT_MARKING]: ['tlp-red'] }),
      entity(fullDocument, { restricted_members: [{ id: 'user' }] }),
      entity(fullDocument, { [RELATION_GRANTED_TO]: ['organization'] }),
      entity(fullDocument, { entity_type: 'Tool' }),
      entity(previewDocument, { entity_type: 'Tool' }),
    ];
    const policies: PulseFieldPolicy[] = [
      preview,
      full,
      { access: PulseAccess.Full, scopes, markingPolicy: null },
      { access: PulseAccess.Off, scopes, markingPolicy: null },
      { access: PulseAccess.NotConnected, scopes, markingPolicy },
    ];
    policies.forEach((policy) => documents.forEach((doc) => {
      expect(matches(pulseQueryClause(policy), doc as unknown as Record<string, any>)).toBe(visiblePulseInformation(doc, policy) !== null);
    }));
  });

  it('should sort a rank the reader may not see as a missing one, after every shown rank in both orders', () => {
    const desc = pulseRankSort(full, 'desc')._script;
    expect(desc).toMatchObject({ type: 'number', order: 'desc' });
    expect(desc.script.params).toEqual({ access: PulseAccess.Full, scopes, excluded: ['tlp-red'], missing: -1 });
    expect(pulseRankSort(preview, 'asc')._script.script.params).toEqual({ access: PulseAccess.Preview, scopes, excluded: [], missing: Number.MAX_SAFE_INTEGER });
    // The full experience without its marking policy shows nothing, as the field does
    expect(pulseRankSort({ access: PulseAccess.Full, scopes, markingPolicy: null }, 'desc')._script.script.params.access).toBe(PulseAccess.Off);
    expect(desc.script.source).toContain("params['_source']['restricted_members']");
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
    const legacy = readPulseSettings({ id: 'settings', pulse_mode: 'contribute', pulse_consent_version: PULSE_CONSENT_VERSION } as unknown as BasicStoreSettings);
    expect(legacy.mode).toBe(PulseMode.ContributeAndRead);
    expect(isPulseContributing(legacy)).toBe(true);
  });

  it('should pause the contribution until the current consent version is accepted', () => {
    // An upgrade changed the consent text: the mode stays, nothing is sent and the platform reads the preview
    [undefined, '2025-01-1'].forEach((consentVersion) => {
      const values = readPulseSettings({ id: 'settings', pulse_mode: 'contribute_and_read', pulse_consent_version: consentVersion } as unknown as BasicStoreSettings);
      expect(values.mode).toBe(PulseMode.ContributeAndRead);
      expect(isPulseConsentCurrent(values)).toBe(false);
      expect(isPulseContributing(values)).toBe(false);
      expect(getPulseAccess(values, true, true)).toBe(PulseAccess.Preview);
    });
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
    const values = readPulseSettings({ id: 'settings', pulse_mode: mode, pulse_consent_version: PULSE_CONSENT_VERSION } as unknown as BasicStoreSettings);
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
