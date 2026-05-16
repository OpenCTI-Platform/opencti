import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { FIVE_MINUTES } from '../../utils/testQuery';
import { checkStreamData, checkStreamGenericContent, fetchStreamEvents } from '../../utils/testStream';
import { logApp, PORT } from '../../../src/config/conf';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE, waitInSec } from '../../../src/database/utils';
import { writeTestDataToFile } from '../../utils/testOutput';
import { doTotal, RAW_EVENTS_SIZE, testCreatedCounter, testDeletedCounter, testMergedCounter, testUpdatedCounter } from '../../utils/syncCountHelper';
import { fetchStreamInfo } from '../../../src/database/stream/stream-handler';

export const dumpEventByTypeToFile = (eventTypeName, eventsByTypesRecords) => {
  const allCreatedEventKeys = Object.keys(eventsByTypesRecords);
  let allCreatedEventCount = '';
  for (let i = 0; i < allCreatedEventKeys.length; i += 1) {
    allCreatedEventCount += `counter['${JSON.stringify(allCreatedEventKeys[i])}'] = ${eventsByTypesRecords[allCreatedEventKeys[i]].length} ;\n`;
  }
  writeTestDataToFile(allCreatedEventCount, `raw-test-${eventTypeName}-event.txt`);
};

const hasAtLeastExpectedEvents = (events) => {
  const createEvents = events.filter((e) => e.type === EVENT_TYPE_CREATE);
  const createEventsByTypes = R.groupBy((e) => e.data.data.type, createEvents);
  const updateEvents = events.filter((e) => e.type === EVENT_TYPE_UPDATE);
  const updateEventsByTypes = R.groupBy((e) => e.data.data.type, updateEvents);
  const deleteEvents = events.filter((e) => e.type === EVENT_TYPE_DELETE);
  const deleteEventsByTypes = R.groupBy((e) => e.data.data.type, deleteEvents);
  const mergeEvents = events.filter((e) => e.type === EVENT_TYPE_MERGE);
  const mergeEventsByTypes = R.groupBy((e) => e.data.data.type, mergeEvents);

  const hasAtLeastExpectedByType = (actualByType, expectedByType) => {
    const keys = Object.keys(expectedByType);
    for (let i = 0; i < keys.length; i += 1) {
      const key = keys[i];
      if (!actualByType[key] || actualByType[key].length < expectedByType[key]) {
        return false;
      }
    }
    return true;
  };

  return hasAtLeastExpectedByType(createEventsByTypes, testCreatedCounter)
    && hasAtLeastExpectedByType(updateEventsByTypes, testUpdatedCounter)
    && hasAtLeastExpectedByType(deleteEventsByTypes, testDeletedCounter)
    && hasAtLeastExpectedByType(mergeEventsByTypes, testMergedCounter)
    && createEvents.length >= doTotal(testCreatedCounter)
    && updateEvents.length >= doTotal(testUpdatedCounter)
    && deleteEvents.length >= doTotal(testDeletedCounter)
    && mergeEvents.length >= doTotal(testMergedCounter)
    && events.length >= RAW_EVENTS_SIZE;
};

const mergeEventsById = (baseEvents, newEvents) => {
  const byEventId = new Map();
  baseEvents.forEach((event) => {
    byEventId.set(event.lastEventId, event);
  });
  newEvents.forEach((event) => {
    byEventId.set(event.lastEventId, event);
  });
  return Array.from(byEventId.values());
};

const collectDuplicateKeys = (values) => {
  const countByKey = new Map();
  values.forEach((value) => {
    if (!value) {
      return;
    }
    countByKey.set(value, (countByKey.get(value) ?? 0) + 1);
  });
  return Array.from(countByKey.entries())
    .filter(([, count]) => count > 1)
    .map(([key, count]) => ({ key, count }));
};

const extractCaseRfiCreateEvents = (events) => {
  return events
    .filter((event) => event.type === EVENT_TYPE_CREATE && event.data?.data?.type === 'case-rfi')
    .map((event) => ({
      lastEventId: event.lastEventId,
      id: event.data?.data?.id,
      created_at: event.data?.data?.extensions?.['extension-definition--4ca6de00-5b0d-45ef-a1dc-ea7279ea910e']?.created_at,
      message: event.data?.message,
      origin: event.origin,
    }));
};

const dumpCaseRfiDiagnostics = (events, label) => {
  const caseRfiCreates = extractCaseRfiCreateEvents(events);
  const duplicateEventIds = collectDuplicateKeys(caseRfiCreates.map((event) => event.lastEventId));
  const duplicateEntityIds = collectDuplicateKeys(caseRfiCreates.map((event) => event.id));
  const diagnostics = {
    label,
    count: caseRfiCreates.length,
    duplicateEventIds,
    duplicateEntityIds,
    events: caseRfiCreates,
  };
  writeTestDataToFile(JSON.stringify(diagnostics, null, 2), `raw-test-case-rfi-${label}.json`);
  logApp.info('[TEST][RAW][CASE-RFI] stream diagnostics', diagnostics);
};

const waitStreamStabilization = async ({
  requiredStableChecks = 3,
  checkIntervalMs = 2000,
  maxWaitMs = 120000,
} = {}) => {
  let stableChecks = 0;
  let previousLastEventId;
  const start = Date.now();
  while (stableChecks < requiredStableChecks) {
    if (Date.now() - start > maxWaitMs) {
      throw new Error(`Stream did not stabilize in ${maxWaitMs}ms`);
    }
    const streamInfo = await fetchStreamInfo();
    const currentLastEventId = streamInfo.lastEventId;
    if (currentLastEventId === previousLastEventId) {
      stableChecks += 1;
    } else {
      stableChecks = 1;
      previousLastEventId = currentLastEventId;
    }
    await waitInSec(checkIntervalMs / 1000);
  }
};

describe('Raw streams tests', () => {
  // We need to check the event format to be sure that everything is setup correctly
  it(
    'Should stream correctly formatted',
    async () => {
      const startTime = new Date().getTime();

      await waitInSec(10);
      await waitStreamStabilization();

      // Fetch stream in batches to avoid missing late async events between phases.
      let events = [];
      let from = '0';
      for (let round = 0; round < 4; round += 1) {
        const batch = await fetchStreamEvents(`http://localhost:${PORT}/stream`, {
          from,
          timeoutMs: 180000,
          inactivityTimeoutMs: 60000,
        });
        dumpCaseRfiDiagnostics(batch, `batch-${round + 1}`);
        events = mergeEventsById(events, batch);
        dumpCaseRfiDiagnostics(events, `aggregated-${round + 1}`);
        const lastBatchEventId = batch.at(-1)?.lastEventId;
        if (lastBatchEventId) {
          from = lastBatchEventId;
        }
        logApp.info('[TEST][RAW] stream batch summary', {
          round: round + 1,
          from,
          batchSize: batch.length,
          aggregatedSize: events.length,
          caseRfiCreateCount: extractCaseRfiCreateEvents(events).length,
        });
        if (hasAtLeastExpectedEvents(events)) {
          break;
        }
        await waitStreamStabilization({ requiredStableChecks: 2, checkIntervalMs: 2000, maxWaitMs: 60000 });
      }
      logApp.info(`[TEST][TIME] time to fetch event: ${new Date().getTime() - startTime}`);

      writeTestDataToFile(JSON.stringify(events), 'raw-test-all-event.json');

      // 00 - Check the number of events and dump information in test result files
      const createEvents = events.filter((e) => e.type === EVENT_TYPE_CREATE);
      const createEventsByTypes = R.groupBy((e) => e.data.data.type, createEvents);
      dumpEventByTypeToFile('create', createEventsByTypes);

      const updateEvents = events.filter((e) => e.type === EVENT_TYPE_UPDATE);
      const updateEventsByTypes = R.groupBy((e) => e.data.data.type, updateEvents);
      dumpEventByTypeToFile('update', updateEventsByTypes);

      const deleteEvents = events.filter((e) => e.type === EVENT_TYPE_DELETE);
      const deleteEventsByTypes = R.groupBy((e) => e.data.data.type, deleteEvents);
      dumpEventByTypeToFile('delete', deleteEventsByTypes);

      logApp.info(`[TEST][TIME] time to dump event in files: ${new Date().getTime() - startTime}`);

      // 01 - CHECK CREATE EVENTS.
      const allExpectedCounterKeys = Object.keys(testCreatedCounter);
      for (let i = 0; i < allExpectedCounterKeys.length; i += 1) {
        const key = allExpectedCounterKeys[i];
        expect(createEventsByTypes[key], `Created ${key} expected but missing from events`).toBeTruthy();
        expect(
          createEventsByTypes[key].length,
          `Created ${key} count should be ${testCreatedCounter[key]} but got ${createEventsByTypes[key].length}`,
        ).toBe(testCreatedCounter[key]);
      }
      expect(createEvents.length).toBe(doTotal(testCreatedCounter));
      for (let createIndex = 0; createIndex < createEvents.length; createIndex += 1) {
        const { data: insideData, origin, type } = createEvents[createIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      logApp.info(`[TEST][TIME] time to check created events: ${new Date().getTime() - startTime}`);
      // 02 - CHECK UPDATE EVENTS.
      const allUpdatedCounterKeys = Object.keys(testUpdatedCounter);
      for (let i = 0; i < allUpdatedCounterKeys.length; i += 1) {
        const key = allUpdatedCounterKeys[i];
        expect(updateEventsByTypes[key], `Updated ${key} expected but missing from events`).toBeTruthy();
        expect(
          updateEventsByTypes[key].length,
          `Updated ${key} count should be ${testUpdatedCounter[key]} but got ${updateEventsByTypes[key].length} ${JSON.stringify(updateEventsByTypes[key])}`,
        ).toBe(testUpdatedCounter[key]);
      }
      expect(updateEvents.length).toBe(doTotal(testUpdatedCounter));
      for (let updateIndex = 0; updateIndex < updateEvents.length; updateIndex += 1) {
        const event = updateEvents[updateIndex];
        const { data: insideData, origin, type } = event;
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
        // Test patch content
        const { patch, reverse_patch } = insideData.context;
        expect(patch).toBeDefined();
        expect(reverse_patch).toBeDefined();
      }
      logApp.info(`[TEST][TIME] time to check updated events: ${new Date().getTime() - startTime}`);
      // 03 - CHECK DELETE EVENTS
      const allDeletedCounterKeys = Object.keys(testDeletedCounter);
      for (let i = 0; i < allDeletedCounterKeys.length; i += 1) {
        const key = allDeletedCounterKeys[i];

        expect(deleteEventsByTypes[key], `Deleted ${key} expected but missing from events`).toBeTruthy();
        expect(
          deleteEventsByTypes[key].length,
          `Deleted ${key} count should be ${testDeletedCounter[key]} but got ${deleteEventsByTypes[key].length}`,
        ).toBe(testDeletedCounter[key]);
      }
      expect(deleteEvents.length).toBe(doTotal(testDeletedCounter));

      for (let delIndex = 0; delIndex < deleteEvents.length; delIndex += 1) {
        const { data: insideData, origin, type } = deleteEvents[delIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      logApp.info(`[TEST][TIME] time to check deleted events: ${new Date().getTime() - startTime}`);
      // 04 - CHECK MERGE EVENTS
      const mergeEvents = events.filter((e) => e.type === EVENT_TYPE_MERGE);
      const mergeEventsByTypes = R.groupBy((e) => e.data.data.type, mergeEvents);
      dumpEventByTypeToFile('merge', mergeEventsByTypes);
      const allMergedCounterKeys = Object.keys(testMergedCounter);
      for (let i = 0; i < allMergedCounterKeys.length; i += 1) {
        const key = allMergedCounterKeys[i];
        expect(
          mergeEventsByTypes[key].length,
          `Merged ${key} count should be ${testMergedCounter[key]} but got ${mergeEventsByTypes[key].length}`,
        ).toBe(testMergedCounter[key]);
      }
      expect(mergeEvents.length).toBe(doTotal(testMergedCounter));

      for (let mergeIndex = 0; mergeIndex < mergeEvents.length; mergeIndex += 1) {
        const { data: insideData, origin } = mergeEvents[mergeIndex];
        const { context } = insideData;
        expect(origin).toBeDefined();
        expect(context.patch).toBeDefined();
        expect(context.reverse_patch).toBeDefined();
        expect(context.sources).toBeDefined();
        expect(context.sources.length > 0).toBeTruthy();
        for (let sourceIndex = 0; sourceIndex < context.sources.length; sourceIndex += 1) {
          const source = context.sources[sourceIndex];
          checkStreamData(EVENT_TYPE_MERGE, source);
        }
      }
      logApp.info(`[TEST][TIME] time to check merged events: ${new Date().getTime() - startTime}`);
      expect(events.length).toBe(RAW_EVENTS_SIZE);
    },
    FIVE_MINUTES,
  );
});
