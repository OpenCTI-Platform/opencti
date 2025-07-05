/* eslint-disable @typescript-eslint/dot-notation */
import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { FIVE_MINUTES } from '../../utils/testQuery';
import { checkStreamData, checkStreamGenericContent, fetchStreamEvents, } from '../../utils/testStream';
import { PORT } from '../../../src/config/conf';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../../../src/database/utils';
import { writeTestDataToFile } from '../../utils/testOutput';
import { doTotal, RAW_EVENTS_SIZE, testCreatedCounter, testDeletedCounter, testMergedCounter, testUpdatedCounter } from '../../utils/syncCountHelper';

export const dumpEventByTypeToFile = (eventTypeName, eventsByTypesRecords) => {
  const allCreatedEventKeys = Object.keys(eventsByTypesRecords);
  let allCreatedEventCount = '';
  for (let i = 0; i < allCreatedEventKeys.length; i += 1) {
    allCreatedEventCount += `counter['${JSON.stringify(allCreatedEventKeys[i])}'] = ${eventsByTypesRecords[allCreatedEventKeys[i]].length} ;\n`;
  }
  writeTestDataToFile(allCreatedEventCount, `raw-test-${eventTypeName}-event.txt`);
};

describe('Raw streams tests', () => {
  // We need to check the event format to be sure that everything is setup correctly
  it(
    'Should stream correctly formatted',
    async () => {
      // Read all events from the beginning.
      const events = await fetchStreamEvents(`http://localhost:${PORT}/stream`, { from: '0' });
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

      // 01 - CHECK CREATE EVENTS.
      const allExpectedCounterKeys = Object.keys(testCreatedCounter);
      for (let i = 0; i < allExpectedCounterKeys.length; i += 1) {
        const key = allExpectedCounterKeys[i];
        expect(createEventsByTypes[key], `Created ${key} expected but missing from events`).toBeTruthy();
        expect(
          createEventsByTypes[key].length,
          `Created ${key} count should be ${testCreatedCounter[key]} but got ${createEventsByTypes[key].length}`
        ).toBe(testCreatedCounter[key]);
      }
      expect(createEvents.length).toBe(doTotal(testCreatedCounter));
      for (let createIndex = 0; createIndex < createEvents.length; createIndex += 1) {
        const { data: insideData, origin, type } = createEvents[createIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }

      // 02 - CHECK UPDATE EVENTS.
      const allUpdatedCounterKeys = Object.keys(testUpdatedCounter);
      for (let i = 0; i < allUpdatedCounterKeys.length; i += 1) {
        const key = allUpdatedCounterKeys[i];
        expect(
          updateEventsByTypes[key].length,
          `Updated ${key} count should be ${testUpdatedCounter[key]} but got ${updateEventsByTypes[key].length} ${JSON.stringify(updateEventsByTypes[key])}`
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

      // 03 - CHECK DELETE EVENTS
      const allDeletedCounterKeys = Object.keys(testDeletedCounter);
      for (let i = 0; i < allDeletedCounterKeys.length; i += 1) {
        const key = allDeletedCounterKeys[i];
        expect(
          deleteEventsByTypes[key].length,
          `Deleted ${key} count should be ${testDeletedCounter[key]} but got ${deleteEventsByTypes[key].length}`
        ).toBe(testDeletedCounter[key]);
      }
      expect(deleteEvents.length).toBe(doTotal(testDeletedCounter));

      for (let delIndex = 0; delIndex < deleteEvents.length; delIndex += 1) {
        const { data: insideData, origin, type } = deleteEvents[delIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      // 04 - CHECK MERGE EVENTS
      const mergeEvents = events.filter((e) => e.type === EVENT_TYPE_MERGE);
      const mergeEventsByTypes = R.groupBy((e) => e.data.data.type, mergeEvents);
      dumpEventByTypeToFile('merge', mergeEventsByTypes);
      const allMergedCounterKeys = Object.keys(testMergedCounter);
      for (let i = 0; i < allMergedCounterKeys.length; i += 1) {
        const key = allMergedCounterKeys[i];
        expect(
          mergeEventsByTypes[key].length,
          `Merged ${key} count should be ${testMergedCounter[key]} but got ${mergeEventsByTypes[key].length}`
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
      expect(events.length).toBe(RAW_EVENTS_SIZE);
    },
    FIVE_MINUTES
  );
});
