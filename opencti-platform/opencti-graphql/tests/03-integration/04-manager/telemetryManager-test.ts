import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { defaultResource, resourceFromAttributes } from '@opentelemetry/resources';
import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { ATTR_SERVICE_INSTANCE_ID, ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { TELEMETRY_SERVICE_NAME, TelemetryMeterManager } from '../../../src/telemetry/TelemetryMeterManager';
import { PLATFORM_VERSION } from '../../../src/config/conf';
import {
  addAskAiQueryCount,
  addChatbotMessageCount,
  addDisseminationCount,
  addNotificationSentCount,
  ASK_AI_FEATURES,
  fetchTelemetryData,
  TELEMETRY_GAUGE_ASK_AI_QUERY,
  TELEMETRY_GAUGE_CHATBOT_MESSAGE,
  TELEMETRY_GAUGE_DISSEMINATION,
  TELEMETRY_GAUGE_DRAFT_CREATION,
  TELEMETRY_GAUGE_EXPORT_GENERATED,
  TELEMETRY_GAUGE_NLQ,
  TELEMETRY_GAUGE_NOTIFICATION_SENT,
} from '../../../src/manager/telemetryManager';
import { redisClearTelemetry, redisGetTelemetry, redisSetTelemetryAdd } from '../../../src/database/redis';
import { waitInSec } from '../../../src/database/utils';
import {
  changeTone,
  convertFilesToStix,
  explain,
  fixSpelling,
  generateContainerReport,
  generateNLQresponse,
  makeLonger,
  makeShorter,
  summarize,
  summarizeFiles,
} from '../../../src/modules/ai/ai-domain';
import { aiActivity, aiForecast, aiHistory } from '../../../src/domain/stixCoreObject';
import { aiSummary } from '../../../src/domain/container';
import { askEntityExport, askListExport } from '../../../src/domain/stix';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../utils/testQuery';
import { addSavedFilter, deleteSavedFilter, savedFilterEditAuthorizedMembers } from '../../../src/modules/savedFilter/savedFilter-domain';

describe('Telemetry manager test coverage', () => {
  let sharedFilterId: string;
  let unsharedFilterId: string;
  let shareWithCreatorFilterId: string;

  // create shared saved filters
  beforeAll(async () => {
    const savedFilter = JSON.stringify({ mode: 'and', filters: [{ key: 'objectLabel', value: [], operator: 'nil' }], filterGroups: [] });

    // Create a saved filter and share it with someone else than the creator
    const sharedSavedFilter = await addSavedFilter(testContext, ADMIN_USER, {
      name: 'telemetry-shared-filter',
      filters: savedFilter,
      scope: 'Incident',
    });
    sharedFilterId = sharedSavedFilter.id;
    await savedFilterEditAuthorizedMembers(testContext, ADMIN_USER, sharedFilterId, [
      { id: ADMIN_USER.id, access_right: 'admin' },
      { id: USER_EDITOR.id, access_right: 'view' },
    ]);

    // Create a saved filter that is NOT shared
    const unshareSavedFilter = await addSavedFilter(testContext, ADMIN_USER, {
      name: 'telemetry-unshared-filter',
      filters: savedFilter,
      scope: 'Incident',
    });
    unsharedFilterId = unshareSavedFilter.id;

    // Create a saved filter that is artificially shared with the creator at creation
    const shareWithCreatorSavedFilter = await addSavedFilter(testContext, ADMIN_USER, {
      name: 'telemetry-unshared-filter',
      filters: savedFilter,
      scope: 'Incident',
    });
    shareWithCreatorFilterId = shareWithCreatorSavedFilter.id;
    await savedFilterEditAuthorizedMembers(testContext, ADMIN_USER, shareWithCreatorFilterId, [
      { id: ADMIN_USER.id, access_right: 'admin' },
    ]);

    // Wait for cache refresh
    await waitInSec(2);
  });

  // delete the shared saved filters
  afterAll(async () => {
    await deleteSavedFilter(testContext, ADMIN_USER, sharedFilterId);
    await deleteSavedFilter(testContext, ADMIN_USER, unsharedFilterId);
    await deleteSavedFilter(testContext, ADMIN_USER, shareWithCreatorFilterId);
  });

  test('Verify that metrics get collected from both elastic and redis', async () => {
    // GIVEN a configured telemetry
    const filigranResource = resourceFromAttributes({
      [ATTR_SERVICE_NAME]: TELEMETRY_SERVICE_NAME,
      [ATTR_SERVICE_VERSION]: PLATFORM_VERSION,
      [ATTR_SERVICE_INSTANCE_ID]: 'api-test-telemetry-id',
      'service.instance.creation': new Date().toUTCString(),
    });
    const resource = defaultResource().merge(filigranResource);

    // no readers so no data is sent for this test
    const filigranMeterProvider = new MeterProvider(({ resource, readers: [] }));
    const filigranTelemetryMeterManager = new TelemetryMeterManager(filigranMeterProvider);
    filigranTelemetryMeterManager.registerFiligranTelemetry();
    // AND Given starting from clean state in redis
    await redisClearTelemetry();
    const disseminationGaugeValueReset = await redisGetTelemetry(TELEMETRY_GAUGE_DISSEMINATION);
    expect(disseminationGaugeValueReset).toBe(0);
    const draftGaugeValue = await redisGetTelemetry(TELEMETRY_GAUGE_DRAFT_CREATION);
    expect(draftGaugeValue).toBe(0);

    // AND GIVEN some "user event" from this node
    const DISSEMINATION_EVENT_NODE1 = 5;
    const DISSEMINATION_EVENT_NODE2 = 3;
    for (let i = 0; i < DISSEMINATION_EVENT_NODE1; i += 1) {
      await addDisseminationCount();
    }
    // AND GIVEN some "user event" from another node (simulated by a direct redis update)
    await redisSetTelemetryAdd(TELEMETRY_GAUGE_DISSEMINATION, DISSEMINATION_EVENT_NODE2);

    // AND GIVEN some AI / product events counted through the fire-and-forget
    // helpers (scalar key + dimensional "key:attribute" formats)
    const CHATBOT_MESSAGE_EVENTS = 4;
    const ASK_AI_SUMMARIZE_EVENTS = 2;
    const NOTIFICATION_EMAIL_EVENTS = 3;
    for (let i = 0; i < CHATBOT_MESSAGE_EVENTS; i += 1) {
      addChatbotMessageCount();
    }
    for (let i = 0; i < ASK_AI_SUMMARIZE_EVENTS; i += 1) {
      addAskAiQueryCount('summarize');
    }
    for (let i = 0; i < NOTIFICATION_EMAIL_EVENTS; i += 1) {
      addNotificationSentCount('email');
    }

    const loopCount = 3; // 3' max
    let loopCurrent = 0;

    const isRedisUpdatedCallback = async () => {
      const disseminationGaugeValue = await redisGetTelemetry(TELEMETRY_GAUGE_DISSEMINATION);
      const chatbotGaugeValue = await redisGetTelemetry(TELEMETRY_GAUGE_CHATBOT_MESSAGE);
      const askAiGaugeValue = await redisGetTelemetry(`${TELEMETRY_GAUGE_ASK_AI_QUERY}:summarize`);
      const notificationGaugeValue = await redisGetTelemetry(`${TELEMETRY_GAUGE_NOTIFICATION_SENT}:email`);
      return disseminationGaugeValue === (DISSEMINATION_EVENT_NODE1 + DISSEMINATION_EVENT_NODE2)
        && chatbotGaugeValue === CHATBOT_MESSAGE_EVENTS
        && askAiGaugeValue === ASK_AI_SUMMARIZE_EVENTS
        && notificationGaugeValue === NOTIFICATION_EMAIL_EVENTS;
    };
    let isRedisUpdated = await isRedisUpdatedCallback();
    while (!isRedisUpdated && loopCurrent < loopCount) {
      await waitInSec(1);
      isRedisUpdated = await isRedisUpdatedCallback();
      loopCurrent += 1;
    }

    // WHEN data is fetched from elastic (platform wide gauges) and redis (user event gauge)
    await fetchTelemetryData(filigranTelemetryMeterManager);

    // THEN all data stored in the in-memory class are accurate
    // TODO later: most of them are not working since it depends on previous tests.
    // Need to analyse better how testSetup and globalSetup are working.
    // expect(filigranTelemetryMeterManager.usersCount).toBe(getCounterTotal(ENTITY_TYPE_USER));
    expect(filigranTelemetryMeterManager.disseminationCount).toBe(DISSEMINATION_EVENT_NODE1 + DISSEMINATION_EVENT_NODE2);
    expect(filigranTelemetryMeterManager.instancesCount).toBe(1);
    expect(filigranTelemetryMeterManager.isEEActivated).toBe(1); // 1 mean true
    // AND the new AI / product Redis counters are wired with the right key
    // formats and dimensional attributes
    expect(filigranTelemetryMeterManager.chatbotMessageCount).toBe(CHATBOT_MESSAGE_EVENTS);
    const summarizeItem = filigranTelemetryMeterManager.askAiQueryItems.find((item) => item.attributes.feature === 'summarize');
    expect(summarizeItem?.value).toBe(ASK_AI_SUMMARIZE_EVENTS);
    const fixSpellingItem = filigranTelemetryMeterManager.askAiQueryItems.find((item) => item.attributes.feature === 'fix_spelling');
    expect(fixSpellingItem?.value).toBe(0); // zero-valued datapoints are kept
    const emailItem = filigranTelemetryMeterManager.notificationSentItems.find((item) => item.attributes.channel === 'email');
    expect(emailItem?.value).toBe(NOTIFICATION_EMAIL_EVENTS);
    const webhookItem = filigranTelemetryMeterManager.notificationSentItems.find((item) => item.attributes.channel === 'webhook');
    expect(webhookItem?.value).toBe(0);
    // filigranTelemetryMeterManager.activeConnectorsCount : count cannot be verified since there are many ways to create internal connectors.
    // expect(filigranTelemetryMeterManager.draftCount).toBe(getCounterTotal(ENTITY_TYPE_DRAFT_WORKSPACE));
    // expect(filigranTelemetryMeterManager.workbenchCount).toBe(getCounterTotal(ENTITY_TYPE_WORKSPACE));

    // 1 shared saved filter should be counted: sharedSavedFilter, because it is shared with others than just the creator
    expect(filigranTelemetryMeterManager.sharedSavedFiltersCount).toEqual(1);
  });

  test('AI and export feature entry points increment the usage counters', async () => {
    // GIVEN a clean telemetry state in redis
    await redisClearTelemetry();

    // WHEN the text-based Ask AI features are called with a too-short content,
    // they short-circuit before any LLM call but still count the attempt
    expect(await fixSpelling(testContext, ADMIN_USER, 'test-bus-id', 'abc')).toBe('Content is too short (3)');
    expect(await makeShorter(testContext, ADMIN_USER, 'test-bus-id', 'abc')).toBe('Content is too short (3)');
    expect(await makeLonger(testContext, ADMIN_USER, 'test-bus-id', 'abc')).toBe('Content is too short (3)');
    expect(await changeTone(testContext, ADMIN_USER, 'test-bus-id', 'abc')).toBe('Content is too short (3)');
    expect(await summarize(testContext, ADMIN_USER, 'test-bus-id', 'abc')).toBe('Content is too short (3)');
    expect(await explain(testContext, ADMIN_USER, 'test-bus-id', 'abc')).toBe('Content is too short (3)');

    // AND WHEN the other feature entry points are called without any AI/XTM One
    // configuration, they fail downstream but the counters keep the attempts
    // semantics (incremented at the entry point, before the upstream call)
    const attempt = async (fn: () => Promise<unknown>) => {
      try {
        await fn();
      } catch {
        // Expected without an AI configuration in the test platform.
      }
    };
    await attempt(() => generateContainerReport(testContext, ADMIN_USER, { containerId: 'unknown-container-id' } as never));
    await attempt(() => summarizeFiles(testContext, ADMIN_USER, { elementId: 'unknown-element-id' } as never));
    await attempt(() => convertFilesToStix(testContext, ADMIN_USER, { elementId: 'unknown-element-id' } as never));
    await attempt(() => generateNLQresponse(testContext, ADMIN_USER, { search: 'malware targeting the energy sector' } as never));
    await attempt(() => aiActivity(testContext, ADMIN_USER, { id: 'unknown-entity-id' }));
    await attempt(() => aiForecast(testContext, ADMIN_USER, { id: 'unknown-entity-id' }));
    await attempt(() => aiHistory(testContext, ADMIN_USER, { id: 'unknown-entity-id' }));
    await attempt(() => aiSummary(testContext, ADMIN_USER, { first: 1 }));

    // AND WHEN export generations are requested (no export connector registered:
    // the calls resolve or fail downstream, the attempts are counted either way)
    await attempt(() => askListExport(testContext, ADMIN_USER, { entity_type: 'Report' }, 'application/json', [], {}, 'simple', [], []));
    await attempt(() => askEntityExport(testContext, ADMIN_USER, 'application/json', { id: 'unknown-entity-id', entity_type: 'Report', name: 'unknown' }, 'simple', [], []));

    // THEN every Ask AI feature has been counted exactly once under its
    // dimensional key, and the scalar NLQ / export counters as well.
    // The counters are fire-and-forget, so poll until the writes land.
    const allCountersUpdated = async () => {
      for (let featureIndex = 0; featureIndex < ASK_AI_FEATURES.length; featureIndex += 1) {
        const featureValue = await redisGetTelemetry(`${TELEMETRY_GAUGE_ASK_AI_QUERY}:${ASK_AI_FEATURES[featureIndex]}`);
        if (featureValue !== 1) return false;
      }
      const nlqValue = await redisGetTelemetry(TELEMETRY_GAUGE_NLQ);
      const exportValue = await redisGetTelemetry(TELEMETRY_GAUGE_EXPORT_GENERATED);
      return nlqValue === 1 && exportValue === 2;
    };
    let countersUpdated = await allCountersUpdated();
    let pollCurrent = 0;
    while (!countersUpdated && pollCurrent < 3) {
      await waitInSec(1);
      countersUpdated = await allCountersUpdated();
      pollCurrent += 1;
    }
    for (let featureIndex = 0; featureIndex < ASK_AI_FEATURES.length; featureIndex += 1) {
      const feature = ASK_AI_FEATURES[featureIndex];
      expect(await redisGetTelemetry(`${TELEMETRY_GAUGE_ASK_AI_QUERY}:${feature}`), `feature ${feature} should be counted once`).toBe(1);
    }
    expect(await redisGetTelemetry(TELEMETRY_GAUGE_NLQ)).toBe(1);
    expect(await redisGetTelemetry(TELEMETRY_GAUGE_EXPORT_GENERATED)).toBe(2);
  });
});
