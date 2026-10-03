import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import conf from '../../../src/config/conf';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { getSettings, settingsEditField } from '../../../src/domain/settings';
import { updateAttribute, deleteElementById } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { ENTITY_TYPE_TRIGGER } from '../../../src/modules/notification/notification-types';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';
import { runPulseContribution, runPulseRefresh, utcDay } from '../../../src/modules/xtm/pulse/pulse-domain';
import { runPulseTrendingNotifications } from '../../../src/modules/xtm/pulse/pulse-notifications';
import { computeStableKeys } from '../../../src/modules/xtm/pulse/pulse-hashing';
import { PULSE_CONSENT_VERSION, type BasicStorePulseEntity } from '../../../src/modules/xtm/pulse/pulse-types';
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
      readable
      unavailable_reason
      information { published prevalence platforms_bucket first_seen_network trend trend_series sector_trend community_uniqueness }
    }
  }
`;
const PULSE_TRENDING = gql`
  query PulseTrending($period: PulsePeriod!) {
    pulseTrending(period: $period) {
      readable
      unavailable_reason
      network_items_count
      entries { object_type platforms_bucket trend entity { id entity_type } }
    }
  }
`;
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

  it('should enable Threat Pulse with the consent', async () => {
    const result = await queryAsAdminWithSuccess({
      query: CONFIGURE,
      variables: { input: { mode: 'contribute_and_read', consent_version: PULSE_CONSENT_VERSION, sector_bucket: 'finance', region_bucket: 'europe' } },
    });
    const configuration = result.data?.pulseConfigure;
    expect(configuration).toMatchObject({
      mode: 'contribute_and_read',
      enabled: true,
      readable: true,
      consent_accepted_version: PULSE_CONSENT_VERSION,
      sector_bucket: 'finance',
      region_bucket: 'europe',
    });
    expect(configuration.consent_user_name).toBeTruthy();
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

  it('should hide the network signal below the anonymity threshold', async () => {
    const result = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: sharedIndicatorId } });
    expect(result.data?.pulseEntity).toMatchObject({ readable: true, unavailable_reason: null });
    expect(result.data?.pulseEntity.information).toMatchObject({ published: false, prevalence: 'rare', community_uniqueness: 100, platforms_bucket: null });
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
    expect(result.data?.pulseEntity.information).toMatchObject({
      published: true,
      prevalence: 'widespread',
      platforms_bucket: '5-9',
      first_seen_network: `${utcDay()}T00:00:00.000Z`,
      trend: 'rising',
      sector_trend: 'rising',
      community_uniqueness: 0,
    });
    const filtered = await queryAsAdminWithSuccess({
      query: INDICATORS_BY_PREVALENCE,
      variables: { filters: { mode: 'and', filters: [{ key: 'pulse_prevalence', values: ['widespread'] }], filterGroups: [] } },
    });
    const ids = filtered.data?.indicators.edges.map((edge: { node: { id: string } }) => edge.node.id);
    expect(ids).toContain(sharedIndicatorId);
    expect(ids).not.toContain(redIndicatorId);
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

  it('should purge every contribution of the platform on XTM Hub', async () => {
    const result = await queryAsAdminWithSuccess({ query: PURGE });
    expect(result.data?.pulsePurge.success).toBe(true);
    expect(result.data?.pulsePurge.deleted_records).toBeGreaterThan(0);
    expect(hub.ledger.filter((row) => row.platformId === settingsId)).toHaveLength(0);
  });

  it('should remove the network information when reading is turned off', async () => {
    await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'contribute' } } });
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const entity = await storeLoadById<BasicStorePulseEntity>(testContext, ADMIN_USER, sharedIndicatorId, ENTITY_TYPE_INDICATOR);
    expect(entity.pulse_prevalence).toBeUndefined();
    expect(entity.pulse_information).toBeUndefined();
    expect(entity.pulse_keys).toEqual(computeStableKeys(entity));
    const result = await queryAsAdminWithSuccess({ query: PULSE_ENTITY, variables: { id: sharedIndicatorId } });
    expect(result.data?.pulseEntity).toMatchObject({ readable: false, unavailable_reason: 'not_enabled' });
  });

  it('should send nothing once disabled', async () => {
    await queryAsAdminWithSuccess({ query: CONFIGURE, variables: { input: { mode: 'off' } } });
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const before = hub.requests.length;
    await queryAsAdminWithSuccess({ query: CREATE_INDICATOR, variables: { input: { name: '198.51.100.202', pattern: "[ipv4-addr:value = '198.51.100.202']", pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } } })
      .then((created) => deleteElementById(testContext, ADMIN_USER, created.data?.indicatorAdd.id, ENTITY_TYPE_INDICATOR));
    await runPulseContribution(testContext);
    expect(hub.requests.length).toBe(before);
  });
});
