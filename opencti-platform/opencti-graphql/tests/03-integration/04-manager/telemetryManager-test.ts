import { describe, expect, test } from 'vitest';
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
  fetchTelemetryData,
  TELEMETRY_GAUGE_ASK_AI_QUERY,
  TELEMETRY_GAUGE_CHATBOT_MESSAGE,
  TELEMETRY_GAUGE_DISSEMINATION,
  TELEMETRY_GAUGE_DRAFT_CREATION,
  TELEMETRY_GAUGE_NOTIFICATION_SENT,
} from '../../../src/manager/telemetryManager';
import { redisClearTelemetry, redisGetTelemetry, redisSetTelemetryAdd } from '../../../src/database/redis';
import { waitInSec } from '../../../src/database/utils';

describe('Telemetry manager test coverage', () => {
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
  });
});
