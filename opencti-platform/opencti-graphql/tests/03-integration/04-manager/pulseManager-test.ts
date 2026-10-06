import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import conf, { REDIS_PREFIX } from '../../../src/config/conf';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { getClientBase } from '../../../src/database/redis';
import { getSettings, settingsEditField } from '../../../src/domain/settings';
import { updateAttribute, deleteElementById } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { ENTITY_TYPE_TRIGGER } from '../../../src/modules/notification/notification-types';
import { MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { runPulseContribution, runPulsePendingCleanup, runPulsePreview, runPulseRefresh, unregisterFromPulse, utcDay } from '../../../src/modules/xtm/pulse/pulse-domain';
import {
  redisAddPulseActivity,
  redisBumpPulseConfigGeneration,
  redisBumpPulsePolicyGeneration,
  redisClaimPulseOutbox,
  redisCommitPulseWindow,
  redisDiscardPulseActivity,
  redisGetPulseConfigGeneration,
  redisGetPulseCursor,
  redisGetPulseSalt,
  redisGetPulseState,
  redisRecordPulseSightingIncrease,
  redisSetPulseSalt,
  redisSetPulseState,
  redisTakePulseActivity,
} from '../../../src/modules/xtm/pulse/pulse-cache';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../src/modules/securityPlatform/securityPlatform-types';
import { recordPulseSightingIncrease } from '../../../src/modules/xtm/pulse/pulse-sighting-activity';
import { runPulseTrendingNotifications } from '../../../src/modules/xtm/pulse/pulse-notifications';
import { computeStableKeys } from '../../../src/modules/xtm/pulse/pulse-hashing';
import { PULSE_CONSENT_VERSION, PULSE_SETTINGS_REGION, PULSE_SETTINGS_SECTOR, type BasicStorePulseEntity } from '../../../src/modules/xtm/pulse/pulse-types';
import { PulseHubMock } from '../../utils/pulseHubMock';

const HUB_TOKEN = 'threat-pulse-integration-token';
const SHARED_IP = '198.51.100.201';
const RED_DOMAIN = 'red-only.pulse-test.example';
const MALWARE_NAME = 'PulseIntegrationLoader';
const OTHER_PLATFORMS = ['pulse-peer-1', 'pulse-peer-2', 'pulse-peer-3', 'pulse-peer-4'];

const CONFIGURE = gql`
  mutation PulseConfigure($input: PulseConfigurationInput!) {
    pulseConfigure(input: $input) {
      mode
      enabled
      readable
      scopes
      consent_accepted_version
      consent_user_name
      sector_bucket
      region_bucket
      forced_excluded_markings { definition }
      contribution { total_records days { day records } }
      network { reachable k_threshold read_access }
    }
  }
`;
const PULSE_ENTITY = gql`
  query PulseEntity($id: ID!) {
    pulseEntity(id: $id) {
      access
      readable
      unavailable_reason
      information { published preview prevalence platforms_bucket first_seen_network trend trend_series sector_trend community_uniqueness }
    }
  }
`;
const PULSE_TRENDING = gql`
  query PulseTrending($period: PulsePeriod!, $includePreview: Boolean) {
    pulseTrending(period: $period, include_preview: $includePreview) {
      readable
      preview
      unavailable_reason
      sector_bucket
      region_bucket
      network_items_count
      locked_count
      entries { object_type rank platforms_bucket trend first_seen_network entity { id entity_type } }
    }
  }
`;
const PULSE_STATUS = gql`
  query PulseStatus {
    pulseStatus { mode access readable preview_entities preview_since }
  }
`;
const PREVIEW_IP = '198.51.100.211';
const OUTBOX_IP = '198.51.100.213';
const GREEN_IP = '198.51.100.214';
const LOST_ANSWER_IP = '198.51.100.215';
const MARKED_LATER_IP = '198.51.100.216';
const NARROWED_IP = '198.51.100.217';
const STALE_POLICY_IP = '198.51.100.218';
const PENDING_ACCEPTED_IP = '198.51.100.219';
const FAILED_WINDOW_IP = '198.51.100.220';
const FORMER_CONSENT_IP = '198.51.100.221';
const EXCLUDED_TRENDING_IP = '198.51.100.222';
const OUT_OF_SCOPE_IP = '198.51.100.223';
const ADMITTED_IP = '198.51.100.224';
const OPENED_TOGETHER_IPS = ['198.51.100.225', '198.51.100.226', '198.51.100.227', '198.51.100.228'];
const FORMER_CONSENT_VERSION = '2025-01-1';
const PULSE_CONSENT_STATE = gql`
  query PulseConsentState {
    pulseSettings { mode enabled access consent_accepted_version }
  }
`;
const PREVIEW_RED_DOMAIN = 'red-preview.pulse-test.example';
const PREVIEW_PEERS = ['pulse-preview-1', 'pulse-preview-2', 'pulse-preview-3', 'pulse-preview-4', 'pulse-preview-5'];
const PREVIEW_FORBIDDEN_OPERATIONS = ['pushPulse', 'pulseLookup', 'pulseTrending', 'pulseBenchmark'];
const PULSE_BENCHMARK = gql`
  query PulseBenchmark($period: PulsePeriod!) {
    pulseBenchmark(period: $period) {
      readable
      unavailable_reason
      metrics { object_type event_kind platform_count }
    }
  }
`;
const INDICATORS_BY_PREVALENCE = gql`
  query PulseIndicators($filters: FilterGroup) {
    indicators(filters: $filters, first: 100) {
      edges { node { id pulse { prevalence platforms_bucket } } }
    }
  }
`;
const CREATE_INDICATOR = gql`
  mutation IndicatorAdd($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) { id }
  }
`;
const CREATE_MALWARE = gql`
  mutation MalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) { id }
  }
`;
const CREATE_TRIGGER = gql`
  mutation TriggerKnowledgeLiveAdd($input: TriggerLiveAddInput!) {
    triggerKnowledgeLiveAdd(input: $input) { id }
  }
`;
const ADD_MARKING = gql`
  mutation PulseIndicatorRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
    indicatorRelationAdd(id: $id, input: $input) { id }
  }
`;
const PULSE_SETTINGS = gql`
  query PulseSettings {
    pulseSettings { scopes contribution { total_records } }
  }
`;
const TELEMETRY = gql`
  mutation PulseTelemetry($event: PulseTelemetryEvent!, $surface: PulseSurface!) {
    pulseTelemetry(event: $event, surface: $surface)
  }
`;
const PURGE = gql`
  mutation PulsePurge {
    pulsePurge { success deleted_records }
  }
`;

describe('Threat Pulse manager and API', () => {
  const hub = new PulseHubMock();
  let previousOverride: string | undefined;
  let settingsId: string;
  let sharedIndicatorId: string;
  let redIndicatorId: string;
  let malwareId: string;
  let triggerId: string;

  const seedPeers = async (entityId: string, entityType: string) => {
    const entity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, entityId, entityType);
    const [key] = computeStableKeys(entity);
    const objectType = entityType === ENTITY_TYPE_INDICATOR ? 'indicator' : 'malware';
    hub.seed(OTHER_PLATFORMS.map((platformId) => ({ platformId, key, objectType, eventKind: 'sighted', day: utcDay(), sector: 'finance', region: 'europe' })));
    return key;
  };

  beforeAll(async () => {
    previousOverride = conf.get('xtm:xtmhub_api_override_url');
    conf.set('xtm:xtmhub_api_override_url', await hub.start());
    const { id } = await getSettings(testContext);
    if (!id) throw new Error('The platform settings must exist before the Threat Pulse manager test');
    settingsId = id;
    hub.registerPlatform(settingsId, HUB_TOKEN);
    await updateAttribute(testContext, ADMIN_USER, settingsId, ENTITY_TYPE_SETTINGS, [{ key: 'xtm_hub_token', value: [HUB_TOKEN] }]);
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
  });

  afterAll(async () => {
    await queryAsAdmin({ query: CONFIGURE, variables: { input: { mode: 'off' } } });
    await updateAttribute(testContext, ADMIN_USER, settingsId, ENTITY_TYPE_SETTINGS, [{ key: 'xtm_hub_token', value: [] }]);
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    if (triggerId) await deleteElementById(testContext, ADMIN_USER, triggerId, ENTITY_TYPE_TRIGGER);
    if (sharedIndicatorId) await deleteElementById(testContext, ADMIN_USER, sharedIndicatorId, ENTITY_TYPE_INDICATOR);
    if (redIndicatorId) await deleteElementById(testContext, ADMIN_USER, redIndicatorId, ENTITY_TYPE_INDICATOR);
    if (malwareId) await deleteElementById(testContext, ADMIN_USER, malwareId, ENTITY_TYPE_MALWARE);
    conf.set('xtm:xtmhub_api_override_url', previousOverride);
    await hub.stop();
  });

  it('should refuse to enable Threat Pulse without the consent', async () => {
    const result = await queryAsAdmin({ query: CONFIGURE, variables: { input: { mode: 'contribute_and_read' } } });
    expect(result.errors?.[0]?.message).toContain('consent');
  });

  it('should refuse a Threat Pulse change through the generic settings edition', async () => {
    await expect(settingsEditField(testContext, ADMIN_USER, settingsId, [{ key: 'pulse_mode', value: ['contribute_and_read'] }]))
      .rejects.toThrow(/Threat Pulse/);
  });

  it('should keep both of two concurrent configuration changes', async () => {
    const before = (await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'preview' } } })).data?.pulseConfigure;
    // Each change keeps the fields it leaves out as they are: the second one serialized must start from the first.
    await Promise.all([
      queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'preview', sector_bucket: 'healthcare' } } }),
      queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'preview', region_bucket: 'middle_east' } } }),
    ]);
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const after = (await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'preview' } } })).data?.pulseConfigure;
    expect([after.sector_bucket, after.region_bucket]).toEqual(['healthcare', 'middle_east']);
    // An unset bucket cannot be set back through the mutation: the settings return to what they were directly.
    await updateAttribute(testContext, ADMIN_USER, settingsId, ENTITY_TYPE_SETTINGS, [
      { key: PULSE_SETTINGS_SECTOR, value: before.sector_bucket ? [before.sector_bucket] : [] },
      { key: PULSE_SETTINGS_REGION, value: before.region_bucket ? [before.region_bucket] : [] },
    ]);
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
  });

  describe('preview (the default mode)', () => {
    let previewIndicatorId: string;
    let previewRedIndicatorId: string;

    afterAll(async () => {
      if (previewIndicatorId) await deleteElementById(testContext, ADMIN_USER, previewIndicatorId, ENTITY_TYPE_INDICATOR);
      if (previewRedIndicatorId) await deleteElementById(testContext, ADMIN_USER, previewRedIndicatorId, ENTITY_TYPE_INDICATOR);
    });

    it('should match the digest locally and send nothing about the platform', async () => {
      const preview = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: PREVIEW_IP, pattern: `[ipv4-addr:value = '${PREVIEW_IP}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } });
      previewIndicatorId = preview.data?.indicatorAdd.id;
      const red = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: PREVIEW_RED_DOMAIN, pattern: `[domain-name:value = '${PREVIEW_RED_DOMAIN}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name', objectMarking: [MARKING_TLP_RED] } } });
      previewRedIndicatorId = red.data?.indicatorAdd.id;
      for (const entityId of [previewIndicatorId, previewRedIndicatorId]) {
        const entity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, entityId, ENTITY_TYPE_INDICATOR);
        const [key] = computeStableKeys(entity);
        hub.seed(PREVIEW_PEERS.map((platformId) => ({ platformId, key, objectType: 'indicator', eventKind: 'sighted', day: utcDay(), sector: 'finance', region: 'europe' })));
      }

      const before = hub.requests.length;
      const matched = await runPulsePreview(testContext, true);

      expect(matched).toBe(2);
      const requests = hub.requests.slice(before);
      expect(requests.map((request) => request.operation)).toContain('pulseDigest');
      expect(requests.filter((request) => PREVIEW_FORBIDDEN_OPERATIONS.includes(request.operation))).toEqual([]);
      requests.filter((request) => request.operation === 'pulseDigest').forEach((request) => {
        expect(Object.keys(request.variables.input).sort()).toEqual(['day', 'region_bucket', 'sector_bucket']);
        [PREVIEW_IP, PREVIEW_RED_DOMAIN, previewIndicatorId, previewRedIndicatorId].forEach((value) => expect(request.rawBody).not.toContain(value));
      });
    });

    it('should show the coarse signal only, as a preview, and keep the filters working', async () => {
      const result = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: previewIndicatorId } });
      expect(result.data?.pulseEntity).toMatchObject({ access: 'preview', readable: false, unavailable_reason: 'contribution_required' });
      expect(result.data?.pulseEntity.information).toMatchObject({
        published: true,
        preview: true,
        prevalence: 'widespread',
        trend: 'rising',
        platforms_bucket: null,
        first_seen_network: null,
        trend_series: [],
        sector_trend: null,
        community_uniqueness: null,
      });
      const red = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: previewRedIndicatorId } });
      expect(red.data?.pulseEntity.information).toMatchObject({ preview: true, prevalence: 'widespread' });
      const filtered = await queryAsAdminWithSuccess({
        query: INDICATORS_BY_PREVALENCE,
        variables: { filters: { mode: 'and', filters: [{ key: 'pulse_prevalence', values: ['widespread'] }], filterGroups: [] } },
      });
      expect(filtered.data?.indicators.edges.map((edge: { node: { id: string } }) => edge.node.id)).toContain(previewIndicatorId);
      const listed = filtered.data?.indicators.edges.find((edge: { node: { id: string } }) => edge.node.id === previewIndicatorId);
      expect(listed?.node.pulse).toMatchObject({ prevalence: 'widespread', platforms_bucket: null });
      const status = await queryAsAdminWithSuccess({ query: PULSE_STATUS });
      expect(status.data?.pulseStatus).toMatchObject({ mode: 'preview', access: 'preview', readable: false, preview_entities: 2 });
      expect(status.data?.pulseStatus.preview_since).toBeTruthy();
      // The preview matches every object whatever its markings: a user counts only the objects they can read
      const restricted = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: PULSE_STATUS });
      expect(restricted.data?.pulseStatus).toMatchObject({ access: 'preview', preview_entities: 1 });
    });

    it('should name the first trending ranks only when the caller asks for the preview', async () => {
      const refused = await queryAsAdminWithSuccess({ query: PULSE_TRENDING, variables: { period: 'last_7_days' } });
      expect(refused.data?.pulseTrending).toMatchObject({ readable: false, preview: false, unavailable_reason: 'contribution_required', entries: [] });
      const preview = await queryAsAdminWithSuccess({ query: PULSE_TRENDING, variables: { period: 'last_7_days', includePreview: true } });
      const trending = preview.data?.pulseTrending;
      expect(trending).toMatchObject({ readable: true, preview: true, unavailable_reason: null, locked_count: 0 });
      expect(trending.network_items_count).toBe(2);
      expect(trending.entries.map((entry: { rank: number }) => entry.rank).sort()).toEqual([1, 2]);
      trending.entries.forEach((entry: { platforms_bucket: string | null }) => expect(entry.platforms_bucket).toBeNull());
      const benchmark = await queryAsAdminWithSuccess({ query: PULSE_BENCHMARK, variables: { period: 'last_30_days' } });
      expect(benchmark.data?.pulseBenchmark.readable).toBe(false);
      // The access state comes before the edition: the preview gets the locked benchmark tiles in both editions
      expect(benchmark.data?.pulseBenchmark.unavailable_reason).toBe('contribution_required');
    });

    it('should count the preview events of a platform in preview', async () => {
      const result = await queryAsAdminWithSuccess({ query: TELEMETRY, variables: { event: 'impression', surface: 'entity_card' } });
      expect(result.data?.pulseTelemetry).toBe(true);
    });

    it('should never contribute, look up, read trending or benchmarks in preview, whatever runs', async () => {
      const before = hub.requests.length;
      await runPulseContribution(testContext);
      await runPulseRefresh(testContext, true);
      await runPulseTrendingNotifications(testContext);
      await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: previewIndicatorId } });
      await queryAsAdminWithSuccess({ query: PULSE_TRENDING, variables: { period: 'last_30_days', includePreview: true } });
      await queryAsAdminWithSuccess({ query: PULSE_BENCHMARK, variables: { period: 'last_30_days' } });
      expect(hub.requests.slice(before).filter((request) => PREVIEW_FORBIDDEN_OPERATIONS.includes(request.operation))).toEqual([]);
    });

    it('should read the preview digest of the configured sector and region', async () => {
      await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'preview', sector_bucket: 'finance', region_bucket: 'north_america' } } });
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
      const before = hub.requests.length;
      const preview = await queryAsAdminWithSuccess({ query: PULSE_TRENDING, variables: { period: 'last_7_days', includePreview: true } });
      // The peers contributed from Europe: nothing trends in North America
      expect(preview.data?.pulseTrending).toMatchObject({ preview: true, sector_bucket: 'finance', region_bucket: 'north_america', network_items_count: 0, entries: [] });
      const digests = hub.requests.slice(before).filter((request) => request.operation === 'pulseDigest');
      expect(digests.length).toBeGreaterThan(0);
      digests.forEach((request) => expect(request.variables.input).toMatchObject({ sector_bucket: 'finance', region_bucket: 'north_america' }));
    });
  });

  it('should enable Threat Pulse with the consent', async () => {
    const result = await queryAsAdminWithSuccess({
      query: CONFIGURE,
      variables: { input: { mode: 'contribute_and_read', consent_version: PULSE_CONSENT_VERSION, sector_bucket: 'finance', region_bucket: 'europe' } },
    });
    const configuration = result.data?.pulseConfigure;
    // XTM Hub grants the full reads to a platform that contributed: the preview stays until its first accepted batch
    expect(configuration).toMatchObject({
      mode: 'contribute_and_read',
      enabled: true,
      readable: false,
      consent_accepted_version: PULSE_CONSENT_VERSION,
      sector_bucket: 'finance',
      region_bucket: 'europe',
    });
    expect(configuration.consent_user_name).toBeTruthy();
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    // Still in preview until the first accepted contribution: its preview events count
    const telemetry = await queryAsAdminWithSuccess({ query: TELEMETRY, variables: { event: 'cta_click', surface: 'trending_widget' } });
    expect(telemetry.data?.pulseTelemetry).toBe(true);
    expect(configuration.forced_excluded_markings.map((marking: { definition: string }) => marking.definition)).toEqual(expect.arrayContaining(['TLP:RED', 'TLP:AMBER+STRICT']));
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
  });

  it('should contribute hashes and counts only, never an excluded object or a raw value', async () => {
    const shared = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: SHARED_IP, pattern: `[ipv4-addr:value = '${SHARED_IP}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } });
    sharedIndicatorId = shared.data?.indicatorAdd.id;
    const red = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: RED_DOMAIN, pattern: `[domain-name:value = '${RED_DOMAIN}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name', objectMarking: [MARKING_TLP_RED] } } });
    redIndicatorId = red.data?.indicatorAdd.id;
    const malware = await queryAsAdminWithSuccess({ query: CREATE_MALWARE, variables: { input: { name: MALWARE_NAME, is_family: true } } });
    malwareId = malware.data?.malwareAdd.id;

    const { pushedRecords } = await runPulseContribution(testContext);
    expect(pushedRecords).toBeGreaterThan(0);
    // The first accepted contribution opens the full reads, and only accepted records count in the statistics
    const status = await queryAsAdminWithSuccess({ query: PULSE_STATUS });
    expect(status.data?.pulseStatus).toMatchObject({ mode: 'contribute_and_read', access: 'full', readable: true });
    // The preview events are counted for platforms in preview only, whatever the client sends
    const telemetry = await queryAsAdminWithSuccess({ query: TELEMETRY, variables: { event: 'impression', surface: 'entity_card' } });
    expect(telemetry.data?.pulseTelemetry).toBe(false);
    const settingsAfterPush = await queryAsAdminWithSuccess({ query: PULSE_SETTINGS });
    expect(settingsAfterPush.data?.pulseSettings.contribution.total_records).toBe(pushedRecords);
    const pushes = hub.requests.filter((request) => request.operation === 'pushPulse');
    expect(pushes.length).toBeGreaterThan(0);
    pushes.forEach((push) => {
      [SHARED_IP, RED_DOMAIN, MALWARE_NAME, MALWARE_NAME.toLowerCase(), sharedIndicatorId, redIndicatorId, malwareId].forEach((value) => {
        expect(push.rawBody).not.toContain(value);
      });
    });
    const sharedEntity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, sharedIndicatorId, ENTITY_TYPE_INDICATOR);
    const redEntity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, redIndicatorId, ENTITY_TYPE_INDICATOR);
    const contributedKeys = hub.ledger.filter((row) => row.platformId === settingsId).map((row) => row.key);
    expect(contributedKeys).toEqual(expect.arrayContaining(computeStableKeys(sharedEntity)));
    computeStableKeys(redEntity).forEach((key) => expect(contributedKeys).not.toContain(key));
    expect(sharedEntity.pulse_keys).toEqual(computeStableKeys(sharedEntity));
    expect(redEntity.pulse_keys).toBeUndefined();
  });

  it('should keep the detections of a run that failed before pushing them, and contribute them with the next run', async () => {
    const today = utcDay();
    const malwareEntity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, malwareId, ENTITY_TYPE_MALWARE);
    const malwareKeys = computeStableKeys(malwareEntity);
    const detectedCount = () => hub.ledger
      .filter((row) => row.platformId === settingsId && row.eventKind === 'detected' && row.day === today && malwareKeys.includes(row.key))
      .reduce((total, row) => total + row.count, 0);
    const before = detectedCount();
    const seenAgainBySecurityPlatform = { internal_id: 'pulse-seen-again-detection', fromId: malwareId, fromType: ENTITY_TYPE_MALWARE, toType: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM };
    await recordPulseSightingIncrease(testContext, seenAgainBySecurityPlatform, 2);
    // A run takes the activity, then fails before its batches are pushed or kept in the outbox
    expect(await redisTakePulseActivity(today, 100)).toEqual([{ entityId: malwareId, eventKind: 'detected', count: 2 }]);
    await recordPulseSightingIncrease(testContext, seenAgainBySecurityPlatform, 1);

    await runPulseContribution(testContext);
    // Both detections are contributed once, the activity is acknowledged
    expect(detectedCount()).toBe(before + 3 * malwareKeys.length);
    expect(await redisTakePulseActivity(today, 100)).toEqual([]);
    await runPulseContribution(testContext);
    expect(detectedCount()).toBe(before + 3 * malwareKeys.length);
  });

  it('should never restore the contribution state a purge removed while a push was in flight', async () => {
    const seenAgain = { internal_id: 'pulse-seen-during-purge', fromId: malwareId, fromType: ENTITY_TYPE_MALWARE, toType: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM };
    await recordPulseSightingIncrease(testContext, seenAgain, 1);
    await redisSetPulseState({ contribution_accepted: undefined });
    // XTM Hub accepts the push; before its answer arrives, a purge moves the configuration generation.
    hub.beforeNextAnswer('pushPulse', async () => {
      await redisBumpPulseConfigGeneration();
    });
    const { pushedRecords } = await runPulseContribution(testContext);
    expect(pushedRecords).toBeGreaterThan(0);
    expect((await redisGetPulseState()).contribution_accepted).toBeUndefined();
    await redisSetPulseState({ contribution_accepted: 'true' });
  });

  it('should claim the activity kept in Redis in bounded chunks, counting what a failed run left', async () => {
    const day = '2000-01-01';
    const entries = 5;
    for (let index = 0; index < entries; index += 1) {
      await redisAddPulseActivity(day, `pulse-claim-${index}`, 'sighted', index + 1);
    }
    // A run claims two entries, then stops before its acknowledgement
    const first = await redisTakePulseActivity(day, 2);
    expect(first).toHaveLength(2);
    // The next run gets them again, plus one more within a limit of three
    const second = await redisTakePulseActivity(day, 3);
    expect(second).toHaveLength(3);
    expect(second).toEqual(expect.arrayContaining(first));
    // Without any budget left, only what is already claimed comes back
    expect(await redisTakePulseActivity(day, 0)).toHaveLength(3);
    // Everything is claimed once, with its count
    const all = await redisTakePulseActivity(day, entries);
    expect(all.map(({ entityId, count }) => `${entityId}:${count}`).sort())
      .toEqual(Array.from({ length: entries }, (_, index) => `pulse-claim-${index}:${index + 1}`).sort());
    await redisDiscardPulseActivity([day]);
    expect(await redisTakePulseActivity(day, entries)).toEqual([]);
  });

  it('should contribute the sightings of an object seen again, not only its first one', async () => {
    const today = utcDay();
    const malwareKeys = computeStableKeys(await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, malwareId, ENTITY_TYPE_MALWARE));
    const sightedCount = () => hub.ledger
      .filter((row) => row.platformId === settingsId && row.eventKind === 'sighted' && row.day === today && malwareKeys.includes(row.key))
      .reduce((total, row) => total + row.count, 0);
    const before = sightedCount();
    // An existing sighting seen three more times: its count rises, no relationship is created
    await recordPulseSightingIncrease(testContext, { internal_id: 'pulse-seen-again-sighting', fromId: malwareId, fromType: ENTITY_TYPE_MALWARE, toType: 'Organization' }, 3);
    await runPulseContribution(testContext);
    expect(sightedCount()).toBe(before + 3 * malwareKeys.length);
  });

  it('should leave the increase of a sighting the next run has still to collect to the count it reads', async () => {
    const today = utcDay();
    const malwareKeys = computeStableKeys(await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, malwareId, ENTITY_TYPE_MALWARE));
    const sightedCount = () => hub.ledger
      .filter((row) => row.platformId === settingsId && row.eventKind === 'sighted' && row.day === today && malwareKeys.includes(row.key))
      .reduce((total, row) => total + row.count, 0);
    await runPulseContribution(testContext);
    const before = sightedCount();
    // Created after the last contribution and already raised: the next run reads the raised count with the sighting
    await recordPulseSightingIncrease(testContext, { internal_id: 'pulse-raised-before-collection', fromId: malwareId, fromType: ENTITY_TYPE_MALWARE, toType: 'Organization', created_at: new Date() }, 2);
    await runPulseContribution(testContext);
    expect(sightedCount()).toBe(before);
  });

  it('should count once an increase that raced with the collection of its window, whatever the order', async () => {
    await runPulseContribution(testContext);
    const today = utcDay();
    const previousCursor = await redisGetPulseCursor();
    const object = 'pulse-race-object';
    const raise = (id: string, createdAt: string, total: number, increase: number) => redisRecordPulseSightingIncrease({
      id, createdAt, oldestCollected: '2000-01-01T00:00:00.000Z', total, increase, entityId: object, eventKind: 'sighted',
    });
    const commit = async (cursor: string, sightings: Array<{ id: string; count: number }>) => redisCommitPulseWindow(
      [],
      cursor,
      [today],
      await redisGetPulseConfigGeneration(),
      sightings.map(({ id, count }) => ({ id, count, entityId: object, eventKind: 'sighted' as const })),
    );
    try {
      const createdAt = new Date().toISOString();
      // Raised to 3 after the window read it at 2, before the commit: the commit adds what the read missed
      expect(await raise('pulse-race-read-first', createdAt, 3, 1)).toBe(0);
      // Raised to 5 before the window read it: the read has it all
      expect(await raise('pulse-race-upsert-first', createdAt, 5, 1)).toBe(0);
      expect(await commit(new Date(Date.parse(createdAt) + 1000).toISOString(), [{ id: 'pulse-race-read-first', count: 2 }, { id: 'pulse-race-upsert-first', count: 5 }])).toBe(true);
      expect(await redisTakePulseActivity(today, 100)).toEqual([{ entityId: object, eventKind: 'sighted', count: 1 }]);
      // The late hook of an upsert the window had read adds nothing; the next upsert adds its own increase only
      expect(await raise('pulse-race-upsert-first', createdAt, 5, 1)).toBe(0);
      expect(await raise('pulse-race-read-first', createdAt, 4, 1)).toBe(1);
      expect(await raise('pulse-race-read-first', createdAt, 3, 1)).toBe(0);
    } finally {
      // The activity of this test is acknowledged without being contributed, and the cursor of the suite comes back
      await redisTakePulseActivity(today, 100);
      await commit(previousCursor ?? new Date().toISOString(), []);
    }
  });

  it('should keep the pending batches until XTM Hub accepts them, even after a run stopped once it claimed them', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: OUTBOX_IP, pattern: `[ipv4-addr:value = '${OUTBOX_IP}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } });
    const outboxIndicatorId = created.data?.indicatorAdd.id;
    const entity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, outboxIndicatorId, ENTITY_TYPE_INDICATOR);
    const keys = computeStableKeys(entity);
    const contributed = () => hub.ledger
      .filter((row) => row.platformId === settingsId && keys.includes(row.key))
      .reduce((total, row) => total + row.count, 0);
    const totalRecords = async () => (await queryAsAdminWithSuccess({ query: PULSE_SETTINGS })).data?.pulseSettings.contribution.total_records;
    const recordsBefore = await totalRecords();
    // XTM Hub fails: the batches wait in the outbox, and nothing counts as contributed
    hub.failNext('pushPulse', 'INTERNAL_SERVER_ERROR');
    await runPulseContribution(testContext);
    expect(contributed()).toBe(0);
    expect(await totalRecords()).toBe(recordsBefore);
    // A run claims the pending batches, then stops before XTM Hub answered
    expect((await redisClaimPulseOutbox()).length).toBeGreaterThan(0);
    // The next run claims them again; XTM Hub fails again, they stay claimed
    hub.failNext('pushPulse', 'INTERNAL_SERVER_ERROR');
    await runPulseContribution(testContext);
    expect(contributed()).toBe(0);
    // Accepted once, then settled and counted once
    await runPulseContribution(testContext);
    expect(contributed()).toBe(keys.length);
    expect(await redisClaimPulseOutbox()).toEqual([]);
    const recordsAccepted = await totalRecords();
    expect(recordsAccepted).toBeGreaterThanOrEqual(recordsBefore + keys.length);
    await runPulseContribution(testContext);
    expect(contributed()).toBe(keys.length);
    expect(await totalRecords()).toBe(recordsAccepted);
    await deleteElementById(testContext, ADMIN_USER, outboxIndicatorId, ENTITY_TYPE_INDICATOR);
  });

  it('should count a batch once when XTM Hub recorded it but its answer was lost', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: LOST_ANSWER_IP, pattern: `[ipv4-addr:value = '${LOST_ANSWER_IP}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } });
    const indicatorId = created.data?.indicatorAdd.id;
    const entity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, indicatorId, ENTITY_TYPE_INDICATOR);
    const keys = computeStableKeys(entity);
    const contributed = () => hub.ledger
      .filter((row) => row.platformId === settingsId && keys.includes(row.key))
      .reduce((total, row) => total + row.count, 0);
    hub.loseNextAnswer('pushPulse');
    await runPulseContribution(testContext);
    // Recorded by XTM Hub, unknown to the platform: the batch waits for a retry with its identifier
    expect(contributed()).toBe(keys.length);
    await runPulseContribution(testContext);
    expect(contributed()).toBe(keys.length);
    expect(await redisClaimPulseOutbox()).toEqual([]);
    await deleteElementById(testContext, ADMIN_USER, indicatorId, ENTITY_TYPE_INDICATOR);
  });

  it('should record the pending batches XTM Hub accepted even when the window of the same run then fails', async () => {
    const today = utcDay();
    const addIndicator = async (ip: string) => (await queryAsAdminWithSuccess({
      query: CREATE_INDICATOR,
      variables: { input: { name: ip, pattern: `[ipv4-addr:value = '${ip}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } },
    })).data?.indicatorAdd.id;
    // A batch waits in the outbox: XTM Hub failed the push that carried it
    const pendingId = await addIndicator(PENDING_ACCEPTED_IP);
    hub.failNext('pushPulse', 'INTERNAL_SERVER_ERROR');
    await runPulseContribution(testContext);
    const { last_push_at: before } = await redisGetPulseState();
    // The next run pushes it, then cannot hash its own window: the salt of the day is not cached and XTM Hub fails it
    const failedWindowId = await addIndicator(FAILED_WINDOW_IP);
    const salt = await redisGetPulseSalt(today);
    await redisSetPulseSalt(today, 'not-a-salt');
    hub.failNext('pulseSalt', 'INTERNAL_SERVER_ERROR');
    try {
      await expect(runPulseContribution(testContext)).rejects.toThrow();
    } finally {
      if (salt) await redisSetPulseSalt(today, salt);
    }
    // What XTM Hub accepted at the start of the run is recorded as the platform's latest contribution
    expect(await redisClaimPulseOutbox()).toEqual([]);
    const { last_push_at: after } = await redisGetPulseState();
    expect(Date.parse(after ?? '')).toBeGreaterThan(Date.parse(before ?? '') || 0);
    await deleteElementById(testContext, ADMIN_USER, pendingId, ENTITY_TYPE_INDICATOR);
    await deleteElementById(testContext, ADMIN_USER, failedWindowId, ENTITY_TYPE_INDICATOR);
  });

  it('should send nothing under a former consent version until the current one is accepted', async () => {
    const pushes = () => hub.requests.filter((request) => request.operation === 'pushPulse').length;
    const created = await queryAsAdminWithSuccess({
      query: CREATE_INDICATOR,
      variables: { input: { name: FORMER_CONSENT_IP, pattern: `[ipv4-addr:value = '${FORMER_CONSENT_IP}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } },
    });
    const indicatorId = created.data?.indicatorAdd.id;
    // An upgrade changed the consent text: the version this platform accepted is a former one
    await updateAttribute(testContext, ADMIN_USER, settingsId, ENTITY_TYPE_SETTINGS, [{ key: 'pulse_consent_version', value: [FORMER_CONSENT_VERSION] }]);
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const before = pushes();
    const { pushedRecords } = await runPulseContribution(testContext);
    expect({ pushedRecords, pushes: pushes() }).toEqual({ pushedRecords: 0, pushes: before });
    expect((await queryAsAdminWithSuccess({ query: PULSE_CONSENT_STATE })).data?.pulseSettings)
      .toMatchObject({ mode: 'contribute_and_read', enabled: false, access: 'preview', consent_accepted_version: FORMER_CONSENT_VERSION });
    // Accepted again: the contribution resumes from the renewal on
    await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'contribute_and_read', consent_version: PULSE_CONSENT_VERSION } } });
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    expect((await queryAsAdminWithSuccess({ query: PULSE_CONSENT_STATE })).data?.pulseSettings)
      .toMatchObject({ enabled: true, consent_accepted_version: PULSE_CONSENT_VERSION });
    await deleteElementById(testContext, ADMIN_USER, indicatorId, ENTITY_TYPE_INDICATOR);
  });

  it('should hide the network signal below the anonymity threshold', async () => {
    const result = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: sharedIndicatorId } });
    expect(result.data?.pulseEntity).toMatchObject({ readable: true, unavailable_reason: null });
    expect(result.data?.pulseEntity.information).toMatchObject({ published: false, prevalence: null, community_uniqueness: 100, platforms_bucket: null });
  });

  it('should never look up an excluded object', async () => {
    const before = hub.requests.filter((request) => request.operation === 'pulseLookup').length;
    const result = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: redIndicatorId } });
    expect(result.data?.pulseEntity).toMatchObject({ readable: false, unavailable_reason: 'excluded', information: null });
    expect(hub.requests.filter((request) => request.operation === 'pulseLookup').length).toBe(before);
  });

  it('should expose the network signal once k platforms contributed, through the nightly refresh and the filters', async () => {
    await seedPeers(sharedIndicatorId, ENTITY_TYPE_INDICATOR);
    await seedPeers(malwareId, ENTITY_TYPE_MALWARE);
    const refreshed = await runPulseRefresh(testContext, true);
    expect(refreshed).toBeGreaterThanOrEqual(2);
    const result = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: sharedIndicatorId } });
    const information = result.data?.pulseEntity.information;
    expect(information).toMatchObject({
      published: true,
      prevalence: 'widespread',
      platforms_bucket: '5-9',
      trend: 'rising',
      sector_trend: 'rising',
      community_uniqueness: 0,
    });
    expect(new Date(information.first_seen_network).toISOString()).toBe(`${utcDay()}T00:00:00.000Z`);
    const filtered = await queryAsAdminWithSuccess({
      query: INDICATORS_BY_PREVALENCE,
      variables: { filters: { mode: 'and', filters: [{ key: 'pulse_prevalence', values: ['widespread'] }], filterGroups: [] } },
    });
    const ids = filtered.data?.indicators.edges.map((edge: { node: { id: string } }) => edge.node.id);
    expect(ids).toContain(sharedIndicatorId);
    expect(ids).not.toContain(redIndicatorId);
    const listed = filtered.data?.indicators.edges.find((edge: { node: { id: string } }) => edge.node.id === sharedIndicatorId);
    expect(listed?.node.pulse).toMatchObject({ prevalence: 'widespread', platforms_bucket: '5-9' });
  });

  it('should resolve trending items to the local entities only', async () => {
    const result = await queryAsAdminWithSuccess({ query: PULSE_TRENDING, variables: { period: 'last_7_days' } });
    const trending = result.data?.pulseTrending;
    expect(trending.readable).toBe(true);
    expect(trending.network_items_count).toBeGreaterThanOrEqual(2);
    const entityIds = trending.entries.map((entry: { entity: { id: string } }) => entry.entity.id);
    expect(entityIds).toEqual(expect.arrayContaining([sharedIndicatorId, malwareId]));
    expect(entityIds).not.toContain(redIndicatorId);
  });

  it('should keep the network first seen day of a trending item null when XTM Hub withholds it', async () => {
    hub.withholdTrendingFirstSeen = true;
    try {
      const result = await queryAsAdminWithSuccess({ query: PULSE_TRENDING, variables: { period: 'last_30_days' } });
      const entries = result.data?.pulseTrending.entries;
      expect(entries.length).toBeGreaterThan(0);
      entries.forEach((entry: { first_seen_network: string | null }) => expect(entry.first_seen_network).toBeNull());
    } finally {
      hub.withholdTrendingFirstSeen = false;
    }
  });

  it('should look an object up again once the values it is matched on changed, whatever the cached lookup', async () => {
    const lookups = () => hub.requests.filter((request) => request.operation === 'pulseLookup').length;
    // Looked up once, then served from the cache
    await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: malwareId } });
    const afterFirst = lookups();
    await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: malwareId } });
    expect(lookups()).toBe(afterFirst);
    // A new alias changes the keys: the cached community data no longer applies
    await updateAttribute(testContext, ADMIN_USER, malwareId, ENTITY_TYPE_MALWARE, [{ key: 'aliases', value: ['PulseIntegrationAlias'] }]);
    await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: malwareId } });
    expect(lookups()).toBe(afterFirst + 1);
    const looked = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, malwareId, ENTITY_TYPE_MALWARE);
    expect(looked.pulse_keys).toEqual(computeStableKeys(looked));
    await updateAttribute(testContext, ADMIN_USER, malwareId, ENTITY_TYPE_MALWARE, [{ key: 'aliases', value: [] }]);
  });

  it('should send the lookups of objects opened at the same time to XTM Hub together', async () => {
    const lookups = () => hub.requests.filter((request) => request.operation === 'pulseLookup').length;
    const ids: string[] = [];
    for (let index = 0; index < OPENED_TOGETHER_IPS.length; index += 1) {
      const value = OPENED_TOGETHER_IPS[index];
      const created = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: value, pattern: `[ipv4-addr:value = '${value}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } });
      ids.push(created.data?.indicatorAdd.id);
    }
    const before = lookups();
    const results = await Promise.all(ids.map((id) => queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id } })));
    results.forEach((result) => expect(result.data?.pulseEntity).toMatchObject({ readable: true, unavailable_reason: null }));
    // Looked up together, not one after the other under the lock: fewer requests than objects (one when they reach the
    // same batch, which a slow runner may split)
    expect(lookups() - before).toBeGreaterThan(0);
    expect(lookups() - before).toBeLessThan(ids.length);
    for (let index = 0; index < ids.length; index += 1) {
      await deleteElementById(testContext, ADMIN_USER, ids[index], ENTITY_TYPE_INDICATOR);
    }
  });

  it('should never send the batches built under a scope the administrator narrowed since', async () => {
    const configure = async (input: Record<string, unknown>) => {
      await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'contribute_and_read', ...input } } });
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    };
    const created = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: NARROWED_IP, pattern: `[ipv4-addr:value = '${NARROWED_IP}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } });
    const indicatorId = created.data?.indicatorAdd.id;
    const keys = computeStableKeys(await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, indicatorId, ENTITY_TYPE_INDICATOR));
    const contributed = () => hub.ledger.filter((row) => row.platformId === settingsId && keys.includes(row.key)).length;
    const scopes: string[] = (await queryAsAdminWithSuccess({ query: PULSE_SETTINGS })).data?.pulseSettings.scopes;
    // The batch waits in the outbox, then indicators leave the scope
    hub.failNext('pushPulse', 'INTERNAL_SERVER_ERROR');
    await runPulseContribution(testContext);
    expect(contributed()).toBe(0);
    await configure({ scopes: scopes.filter((scope) => scope !== ENTITY_TYPE_INDICATOR) });
    await runPulseContribution(testContext);
    expect(contributed()).toBe(0);
    expect(await redisClaimPulseOutbox()).toEqual([]);
    await configure({ scopes });
    await deleteElementById(testContext, ADMIN_USER, indicatorId, ENTITY_TYPE_INDICATOR);
  });

  it('should never contribute the activity that happened while a scope was left out, once the administrator adds it back', async () => {
    const configure = async (input: Record<string, unknown>) => {
      await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'contribute_and_read', ...input } } });
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    };
    const createIndicator = async (value: string) => {
      const created = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: value, pattern: `[ipv4-addr:value = '${value}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } });
      const id: string = created.data?.indicatorAdd.id;
      const keys = computeStableKeys(await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, id, ENTITY_TYPE_INDICATOR));
      return { id, contributed: () => hub.ledger.filter((row) => row.platformId === settingsId && keys.includes(row.key)).length };
    };
    const scopes: string[] = (await queryAsAdminWithSuccess({ query: PULSE_SETTINGS })).data?.pulseSettings.scopes;
    await runPulseContribution(testContext);
    await configure({ scopes: scopes.filter((scope) => scope !== ENTITY_TYPE_INDICATOR) });
    // Created while indicators are out of the scope, then indicators come back before the next run
    const outOfScope = await createIndicator(OUT_OF_SCOPE_IP);
    await configure({ scopes });
    const admitted = await createIndicator(ADMITTED_IP);
    await runPulseContribution(testContext);
    await runPulseContribution(testContext);
    expect(outOfScope.contributed()).toBe(0);
    expect(admitted.contributed()).toBeGreaterThan(0);
    await deleteElementById(testContext, ADMIN_USER, outOfScope.id, ENTITY_TYPE_INDICATOR);
    await deleteElementById(testContext, ADMIN_USER, admitted.id, ENTITY_TYPE_INDICATOR);
  });

  it('should never send a pending batch built under a policy narrowed since, even when its discard did not happen', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: STALE_POLICY_IP, pattern: `[ipv4-addr:value = '${STALE_POLICY_IP}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } });
    const indicatorId = created.data?.indicatorAdd.id;
    const keys = computeStableKeys(await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, indicatorId, ENTITY_TYPE_INDICATOR));
    const contributed = () => hub.ledger.filter((row) => row.platformId === settingsId && keys.includes(row.key)).length;
    hub.failNext('pushPulse', 'INTERNAL_SERVER_ERROR');
    await runPulseContribution(testContext);
    expect(contributed()).toBe(0);
    // The policy narrowed, but a failure left the pending batches in place
    await redisBumpPulsePolicyGeneration();
    await runPulseContribution(testContext);
    expect(contributed()).toBe(0);
    expect(await redisClaimPulseOutbox()).toEqual([]);
    await deleteElementById(testContext, ADMIN_USER, indicatorId, ENTITY_TYPE_INDICATOR);
  });

  it('should remove the statistics of the objects a narrower scope or a new exclusion takes out', async () => {
    const load = (id: string, type: string) => storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, id, type);
    const configure = async (input: Record<string, unknown>) => {
      await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'contribute_and_read', ...input } } });
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    };
    const green = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: GREEN_IP, pattern: `[ipv4-addr:value = '${GREEN_IP}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr', objectMarking: [MARKING_TLP_GREEN] } } });
    const greenIndicatorId = green.data?.indicatorAdd.id;
    await seedPeers(greenIndicatorId, ENTITY_TYPE_INDICATOR);
    await runPulseRefresh(testContext, true);
    expect((await load(greenIndicatorId, ENTITY_TYPE_INDICATOR)).pulse_information?.updated_at).toBeTruthy();
    const scopes: string[] = (await queryAsAdminWithSuccess({ query: PULSE_SETTINGS })).data?.pulseSettings.scopes;

    // A new exclusion: only the objects with that marking lose their statistics
    await configure({ excluded_markings: [MARKING_TLP_GREEN] });
    expect((await load(greenIndicatorId, ENTITY_TYPE_INDICATOR)).pulse_information).toBeUndefined();
    expect((await load(sharedIndicatorId, ENTITY_TYPE_INDICATOR)).pulse_prevalence).toBe('widespread');

    // A narrower scope: only the objects of the removed type lose theirs
    await configure({ excluded_markings: [], scopes: scopes.filter((scope) => scope !== ENTITY_TYPE_INDICATOR) });
    expect((await load(sharedIndicatorId, ENTITY_TYPE_INDICATOR)).pulse_prevalence).toBeUndefined();
    expect((await load(malwareId, ENTITY_TYPE_MALWARE)).pulse_prevalence).toBeDefined();

    await configure({ scopes });
    expect(await runPulseRefresh(testContext, true)).toBeGreaterThanOrEqual(2);
    expect((await load(sharedIndicatorId, ENTITY_TYPE_INDICATOR)).pulse_prevalence).toBe('widespread');
    await deleteElementById(testContext, ADMIN_USER, greenIndicatorId, ENTITY_TYPE_INDICATOR);
  });

  it('should remove the statistics of an object that received an excluded marking since its last refresh', async () => {
    const load = async (id: string) => storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, id, ENTITY_TYPE_INDICATOR);
    const created = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: MARKED_LATER_IP, pattern: `[ipv4-addr:value = '${MARKED_LATER_IP}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } });
    const indicatorId = created.data?.indicatorAdd.id;
    await seedPeers(indicatorId, ENTITY_TYPE_INDICATOR);
    await runPulseRefresh(testContext, true);
    // Four peers, below the anonymity threshold: statistics without a prevalence
    const refreshed = await load(indicatorId);
    expect(refreshed.pulse_information?.updated_at).toBeTruthy();
    expect(refreshed.pulse_community_uniqueness).toBe(100);
    await queryAsAdminWithSuccess({ query: ADD_MARKING, variables: { id: indicatorId, input: { toId: MARKING_TLP_RED, relationship_type: 'object-marking' } } });
    await runPulseRefresh(testContext, true);
    const marked = await load(indicatorId);
    expect(marked.pulse_prevalence ?? null).toBeNull();
    expect(marked.pulse_information ?? null).toBeNull();
    await deleteElementById(testContext, ADMIN_USER, indicatorId, ENTITY_TYPE_INDICATOR);
  });

  it('should leave an object excluded since its last refresh out of the trending list, whatever keys it kept', async () => {
    const configure = async (input: Record<string, unknown>) => {
      await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'contribute_and_read', ...input } } });
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    };
    const created = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: EXCLUDED_TRENDING_IP, pattern: `[ipv4-addr:value = '${EXCLUDED_TRENDING_IP}']`, pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr', objectMarking: [MARKING_TLP_GREEN] } } });
    const indicatorId = created.data?.indicatorAdd.id;
    // Five peers: the object trends in the sector
    const key = await seedPeers(indicatorId, ENTITY_TYPE_INDICATOR);
    hub.seed([{ platformId: 'pulse-peer-5', key, objectType: 'indicator', eventKind: 'sighted', day: utcDay(), sector: 'finance', region: 'europe' }]);
    await runPulseRefresh(testContext, true);
    expect((await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, indicatorId, ENTITY_TYPE_INDICATOR)).pulse_keys).toContain(key);
    // A period no earlier test read: the answer of XTM Hub is not cached yet
    const trendingIds = async () => {
      const { data } = await queryAsAdminWithSuccess({ query: PULSE_TRENDING, variables: { period: 'last_90_days' } });
      return data?.pulseTrending.entries.map((entry: { entity: { id: string } }) => entry.entity.id);
    };
    expect(await trendingIds()).toContain(indicatorId);
    // Excluded since: XTM Hub still lists its hash, the platform no longer shows it
    await configure({ excluded_markings: [MARKING_TLP_GREEN] });
    try {
      expect(await trendingIds()).not.toContain(indicatorId);
    } finally {
      await configure({ excluded_markings: [] });
      await deleteElementById(testContext, ADMIN_USER, indicatorId, ENTITY_TYPE_INDICATOR);
    }
  });

  it('should keep the benchmark for Enterprise Edition platforms', async () => {
    const result = await queryAsAdminWithSuccess({ query: PULSE_BENCHMARK, variables: { period: 'last_30_days' } });
    const benchmark = result.data?.pulseBenchmark;
    if (benchmark.readable) {
      expect(benchmark.metrics.length).toBeGreaterThan(0);
    } else {
      expect(benchmark.unavailable_reason).toBe('enterprise_edition_required');
    }
  });

  it('should notify the triggers listening to objects trending in the sector, once', async () => {
    const trigger = await queryAsAdminWithSuccess({
      query: CREATE_TRIGGER,
      variables: { input: { name: 'Threat Pulse trending', event_types: ['pulse_trending'], instance_trigger: false, notifiers: [] } },
    });
    triggerId = trigger.data?.triggerKnowledgeLiveAdd.id;
    resetCacheForEntity(ENTITY_TYPE_TRIGGER);
    const notifications = await runPulseTrendingNotifications(testContext);
    expect(notifications).toBeGreaterThanOrEqual(2);
    expect(await runPulseTrendingNotifications(testContext)).toBe(0);
  });

  it('should notify a trending trigger created later, once', async () => {
    const later = await queryAsAdminWithSuccess({
      query: CREATE_TRIGGER,
      variables: { input: { name: 'Threat Pulse trending later', event_types: ['pulse_trending'], instance_trigger: false, notifiers: [] } },
    });
    const laterTriggerId = later.data?.triggerKnowledgeLiveAdd.id;
    resetCacheForEntity(ENTITY_TYPE_TRIGGER);
    expect(await runPulseTrendingNotifications(testContext)).toBeGreaterThanOrEqual(2);
    expect(await runPulseTrendingNotifications(testContext)).toBe(0);
    await deleteElementById(testContext, ADMIN_USER, laterTriggerId, ENTITY_TYPE_TRIGGER);
    resetCacheForEntity(ENTITY_TYPE_TRIGGER);
  });

  it('should fall back to the preview when the trending notifications read a lapse', async () => {
    // The answers of XTM Hub are cached: the notification run asks again. The client key prefix applies neither to
    // the KEYS pattern nor to the names it returns, while DEL adds it.
    const cached = await getClientBase().keys(`${REDIS_PREFIX}{pulse}:response:trending:*`);
    if (cached.length > 0) {
      await getClientBase().del(...cached.map((key) => key.slice(REDIS_PREFIX.length)));
    }
    hub.failNext('pulseTrending', 'PULSE_CONTRIBUTION_REQUIRED');
    expect(await runPulseTrendingNotifications(testContext)).toBe(0);
    expect((await redisGetPulseState()).contribution_lapsed).toBe('true');
    const entity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, sharedIndicatorId, ENTITY_TYPE_INDICATOR);
    expect(entity.pulse_information).toBeUndefined();
    // Back to the full experience for the next tests, as an accepted contribution does
    await redisSetPulseState({ contribution_lapsed: undefined });
  });

  it('should fall back to the preview when XTM Hub requires a contribution, and recover with the next accepted one', async () => {
    hub.failNext('pulseLookup', 'PULSE_CONTRIBUTION_REQUIRED');
    await expect(runPulseRefresh(testContext, true)).rejects.toThrow();
    const lapsed = await queryAsAdminWithSuccess({ query: PULSE_STATUS });
    expect(lapsed.data?.pulseStatus).toMatchObject({ mode: 'contribute_and_read', access: 'preview', readable: false });
    const lapsedEntity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, sharedIndicatorId, ENTITY_TYPE_INDICATOR);
    expect(lapsedEntity.pulse_information).toBeUndefined();
    expect(await runPulsePreview(testContext, true)).toBeGreaterThanOrEqual(1);
    const preview = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: sharedIndicatorId } });
    expect(preview.data?.pulseEntity).toMatchObject({ access: 'preview', information: { preview: true } });

    // The window that ends where an earlier test removed an exclusion goes first
    await runPulseContribution(testContext);
    const created = await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: '198.51.100.212', pattern: "[ipv4-addr:value = '198.51.100.212']", pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } });
    const { pushedRecords } = await runPulseContribution(testContext);
    expect(pushedRecords).toBeGreaterThan(0);
    await deleteElementById(testContext, ADMIN_USER, created.data?.indicatorAdd.id, ENTITY_TYPE_INDICATOR);
    const recovered = await queryAsAdminWithSuccess({ query: PULSE_STATUS });
    expect(recovered.data?.pulseStatus).toMatchObject({ access: 'full', readable: true });
    expect(await runPulseRefresh(testContext, true)).toBeGreaterThanOrEqual(2);
    const full = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: sharedIndicatorId } });
    expect(full.data?.pulseEntity).toMatchObject({ access: 'full', readable: true, information: { preview: false, platforms_bucket: '5-9' } });
  });

  it('should keep the local contribution tracking when XTM Hub does not purge', async () => {
    const contributedRows = hub.ledger.filter((row) => row.platformId === settingsId).length;
    const before = await queryAsAdminWithSuccess({ query: PULSE_SETTINGS });
    hub.refuseNextPurge();
    const result = await queryAsAdminWithSuccess({ query: PURGE });
    expect(result.data?.pulsePurge).toEqual({ success: false, deleted_records: 0 });
    expect(hub.ledger.filter((row) => row.platformId === settingsId)).toHaveLength(contributedRows);
    const after = await queryAsAdminWithSuccess({ query: PULSE_SETTINGS });
    expect(after.data?.pulseSettings.contribution.total_records).toBe(before.data?.pulseSettings.contribution.total_records);
    expect(after.data?.pulseSettings.contribution.total_records).toBeGreaterThan(0);
  });

  it('should purge every contribution of the platform on XTM Hub', async () => {
    const result = await queryAsAdminWithSuccess({ query: PURGE });
    expect(result.data?.pulsePurge.success).toBe(true);
    expect(result.data?.pulsePurge.deleted_records).toBeGreaterThan(0);
    expect(hub.ledger.filter((row) => row.platformId === settingsId)).toHaveLength(0);
    // XTM Hub holds no contribution of the platform any more: back to the preview until the next accepted one
    const status = await queryAsAdminWithSuccess({ query: PULSE_STATUS });
    expect(status.data?.pulseStatus).toMatchObject({ mode: 'contribute_and_read', access: 'preview', readable: false });
  });

  it('should remove the full statistics when the contribution stops, back to the preview', async () => {
    await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'preview' } } });
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const entity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, sharedIndicatorId, ENTITY_TYPE_INDICATOR);
    expect(entity.pulse_prevalence).toBeUndefined();
    expect(entity.pulse_information).toBeUndefined();
    expect(entity.pulse_keys).toEqual(computeStableKeys(entity));
    const result = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: sharedIndicatorId } });
    expect(result.data?.pulseEntity).toMatchObject({ access: 'preview', readable: false, unavailable_reason: 'contribution_required', information: null });
  });

  it('should send nothing and download nothing once turned off', async () => {
    await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'off' } } });
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const before = hub.requests.length;
    await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: '198.51.100.202', pattern: "[ipv4-addr:value = '198.51.100.202']", pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } })
      .then((created) => deleteElementById(testContext, ADMIN_USER, created.data?.indicatorAdd.id, ENTITY_TYPE_INDICATOR));
    await runPulseContribution(testContext);
    await runPulsePreview(testContext, true);
    expect(hub.requests.length).toBe(before);
    const result = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: sharedIndicatorId } });
    expect(result.data?.pulseEntity).toMatchObject({ access: 'off', readable: false, unavailable_reason: 'not_enabled' });
  });

  it('should keep neither community data, contribution state nor consent once the platform leaves XTM Hub', async () => {
    await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'contribute_and_read', consent_version: PULSE_CONSENT_VERSION } } });
    await redisSetPulseState({ contribution_accepted: 'true', preview_matched: '3' });
    // The registration itself stays for the next tests: the unregistration writes the Threat Pulse updates alone.
    let written: Array<{ key: string; value: unknown[] }> = [];
    await unregisterFromPulse(testContext, async (pulseUpdates) => {
      written = pulseUpdates;
      await updateAttribute(testContext, ADMIN_USER, settingsId, ENTITY_TYPE_SETTINGS, pulseUpdates);
    });
    expect(written).toEqual([{ key: 'pulse_mode', value: ['preview'] }]);
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const state = await redisGetPulseState();
    expect({ accepted: state.contribution_accepted, matched: state.preview_matched }).toEqual({ accepted: undefined, matched: undefined });
    expect(await redisClaimPulseOutbox()).toEqual([]);
    const entity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, sharedIndicatorId, ENTITY_TYPE_INDICATOR);
    expect(entity.pulse_prevalence).toBeUndefined();
    // Back in the preview: contributing again takes a renewed consent.
    const status = await queryAsAdminWithSuccess({ query: PULSE_STATUS });
    expect(status.data?.pulseStatus).toMatchObject({ mode: 'preview', access: 'preview' });
    const refused = await queryAsAdmin({ query: CONFIGURE, variables: { input: { mode: 'contribute_and_read' } } });
    expect(refused.errors?.[0]?.message).toContain('consent');
    // A platform that was not contributing keeps its mode.
    await unregisterFromPulse(testContext, async (pulseUpdates) => {
      written = pulseUpdates;
    });
    expect(written).toEqual([]);
  });

  it('should replay a cleanup that failed with the next manager cycle, registered on XTM Hub or not', async () => {
    const today = utcDay();
    // A cleanup of the registration left pending: the state and the activity collected for it go
    await redisSetPulseState({ cleanup_pending: 'registration', contribution_accepted: 'true', preview_matched: '5' });
    await redisAddPulseActivity(today, malwareId, 'sighted', 1);
    await runPulsePendingCleanup();
    const afterRegistration = await redisGetPulseState();
    expect({ pending: afterRegistration.cleanup_pending, accepted: afterRegistration.contribution_accepted, matched: afterRegistration.preview_matched })
      .toEqual({ pending: undefined, accepted: undefined, matched: undefined });
    expect(await redisTakePulseActivity(today, 10)).toEqual([]);
    // A cleanup of the network information left pending: the contribution state stays
    await redisSetPulseState({ cleanup_pending: 'network', contribution_accepted: 'true' });
    await runPulsePendingCleanup();
    const afterNetwork = await redisGetPulseState();
    expect({ pending: afterNetwork.cleanup_pending, accepted: afterNetwork.contribution_accepted }).toEqual({ pending: undefined, accepted: 'true' });
    expect((await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, sharedIndicatorId, ENTITY_TYPE_INDICATOR)).pulse_prevalence).toBeUndefined();
    // An opening of the full experience left pending: the replay opens it, without waiting for another accepted push
    await redisSetPulseState({ cleanup_pending: 'opening', contribution_accepted: undefined, contribution_lapsed: 'true' });
    await runPulsePendingCleanup();
    const afterOpening = await redisGetPulseState();
    expect({ pending: afterOpening.cleanup_pending, accepted: afterOpening.contribution_accepted, lapsed: afterOpening.contribution_lapsed })
      .toEqual({ pending: undefined, accepted: 'true', lapsed: undefined });
    // A partial cleanup left pending keeps its scope until it is replayed
    await redisSetPulseState({ cleanup_pending: 'scope', cleanup_scope: JSON.stringify({ entityTypes: ['Tool'], markingIds: [] }) });
    await runPulsePendingCleanup();
    const afterScope = await redisGetPulseState();
    expect({ pending: afterScope.cleanup_pending, scope: afterScope.cleanup_scope }).toEqual({ pending: undefined, scope: undefined });
    await redisSetPulseState({ contribution_accepted: undefined });
  });
});
