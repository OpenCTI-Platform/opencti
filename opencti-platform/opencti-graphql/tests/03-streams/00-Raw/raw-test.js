import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { FIVE_MINUTES, RAW_EVENTS_SIZE } from '../../utils/testQuery';
import { checkStreamData, checkStreamGenericContent, fetchStreamEvents, } from '../../utils/testStream';
import { PORT } from '../../../src/config/conf';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../../../src/database/utils';

describe('Raw streams tests', () => {
  // We need to check the event format to be sure that everything is setup correctly
  it(
    'Should stream correctly formatted',
    async () => {
      // Read all events from the beginning.
      const events = await fetchStreamEvents(`http://localhost:${PORT}/stream`, { from: '0' });
      // Check the number of events
      expect(events.length).toBe(RAW_EVENTS_SIZE);
      // 01 - CHECK CREATE EVENTS
      const createEvents = events.filter((e) => e.type === EVENT_TYPE_CREATE);
      expect(createEvents.length).toBe(601);
      // Check some events count
      const createEventsByTypes = R.groupBy((e) => e.data.data.type, createEvents);
      expect(createEventsByTypes['marking-definition'].length).toBe(8);
      expect(createEventsByTypes['external-reference'].length).toBe(17);
      expect(createEventsByTypes.label.length).toBe(15);
      expect(createEventsByTypes.identity.length).toBe(19);
      expect(createEventsByTypes.relationship.length).toBe(123);
      expect(createEventsByTypes.indicator.length).toBe(30);
      expect(createEventsByTypes['attack-pattern'].length).toBe(7);
      expect(createEventsByTypes.report.length).toBe(5);
      expect(createEventsByTypes.tool.length).toBe(2);
      expect(createEventsByTypes.vulnerability.length).toBe(7);
      for (let createIndex = 0; createIndex < createEvents.length; createIndex += 1) {
        const { data: insideData, origin, type } = createEvents[createIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      // 02 - CHECK UPDATE EVENTS
      const updateEvents = events.filter((e) => e.type === EVENT_TYPE_UPDATE);
      expect(updateEvents.length).toBe(114);
      const updateEventsByTypes = R.groupBy((e) => e.data.data.type, updateEvents);
      expect(updateEventsByTypes.report.length).toBe(3);
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
      const deleteEvents = events.filter((e) => e.type === EVENT_TYPE_DELETE);
      expect(deleteEvents.length).toBe(58);
      // const deleteEventsByTypes = R.groupBy((e) => e.data.data.type, deleteEvents);
      for (let delIndex = 0; delIndex < deleteEvents.length; delIndex += 1) {
        const { data: insideData, origin, type } = deleteEvents[delIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      // 04 - CHECK MERGE EVENTS
      const mergeEvents = events.filter((e) => e.type === EVENT_TYPE_MERGE);
      expect(mergeEvents.length).toBe(3);
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
    },
    FIVE_MINUTES
  );

  // Based on all events of a specific element, can we reconstruct the final state correctly?
  it(
    'Should events dependencies available',
    async () => {
      const events = await fetchStreamEvents(`http://localhost:${PORT}/stream`, { from: '0' });
      const contextWithDeletionEvents = events.filter(
        (e) => {
          const { context } = e.data;
          return (context?.deletions || []).length > 0 || (context?.sources || []).length > 0;
        }
      );
      const deletions = R.flatten(
        contextWithDeletionEvents.map((e) => {
          const { context } = e.data;
          return [...(context?.deletions || []), ...(context?.sources || [])];
        })
      );
      const byTypes = R.groupBy((e) => e.type, deletions);
      expect(byTypes.relationship.length).toBe(8); // Due to merge and sub deletions
      expect(byTypes['threat-actor-group'].length).toBe(6); // Merge of threat actors in test
      expect(byTypes.file.length).toBe(2); // Merge of files in test
    },
    FIVE_MINUTES
  );
});
