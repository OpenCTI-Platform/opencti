/* eslint-disable @typescript-eslint/dot-notation */
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
      // 01 - CHECK CREATE EVENTS.
      const createEvents = events.filter((e) => e.type === EVENT_TYPE_CREATE);
      // Check some events count
      const createEventsByTypes = R.groupBy((e) => e.data.data.type, createEvents);
      expect(createEventsByTypes['marking-definition'].length).toBe(19);
      expect(createEventsByTypes['external-reference'].length).toBe(17);
      expect(createEventsByTypes['kill-chain-phase'].length).toBe(3);
      expect(createEventsByTypes['course-of-action'].length).toBe(3);
      expect(createEventsByTypes.label.length).toBe(15);
      expect(createEventsByTypes.identity.length).toBe(31);
      expect(createEventsByTypes.location.length).toBe(15);
      expect(createEventsByTypes.relationship.length).toBe(136);
      expect(createEventsByTypes.sighting.length).toBe(4);
      expect(createEventsByTypes.indicator.length).toBe(36);
      expect(createEventsByTypes['attack-pattern'].length).toBe(9);
      expect(createEventsByTypes['threat-actor'].length).toBe(13);
      expect(createEventsByTypes['observed-data'].length).toBe(1);
      expect(createEventsByTypes['tracking-number'].length).toBe(1);
      expect(createEventsByTypes.credential.length).toBe(1);
      expect(createEventsByTypes['network-traffic'].length).toBe(1);
      expect(createEventsByTypes['ipv4-addr'].length).toBe(1);
      expect(createEventsByTypes['data-component'].length).toBe(5);
      expect(createEventsByTypes['data-source'].length).toBe(1);
      expect(createEventsByTypes.malware.length).toBe(44);
      expect(createEventsByTypes.software.length).toBe(1);
      expect(createEventsByTypes.file.length).toBe(4);
      expect(createEventsByTypes.campaign.length).toBe(5);
      expect(createEventsByTypes.incident.length).toBe(2);
      expect(createEventsByTypes.report.length).toBe(33);
      expect(createEventsByTypes.tool.length).toBe(2);
      expect(createEventsByTypes.vocabulary.length).toBe(342); // 328 created at init + 2 created in tests + 5 vocabulary organizations types + 7 persona
      expect(createEventsByTypes.vulnerability.length).toBe(7);
      expect(createEvents.length).toBe(776);
      for (let createIndex = 0; createIndex < createEvents.length; createIndex += 1) {
        const { data: insideData, origin, type } = createEvents[createIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      // 02 - CHECK UPDATE EVENTS.
      const updateEvents = events.filter((e) => e.type === EVENT_TYPE_UPDATE);
      const updateEventsByTypes = R.groupBy((e) => e.data.data.type, updateEvents);
      expect(updateEventsByTypes['marking-definition'].length).toBe(2);
      expect(updateEventsByTypes['campaign'].length).toBe(7);
      expect(updateEventsByTypes['relationship'].length).toBe(8);
      expect(updateEventsByTypes['identity'].length).toBe(12);
      expect(updateEventsByTypes['malware'].length).toBe(16);
      expect(updateEventsByTypes['intrusion-set'].length).toBe(4);
      expect(updateEventsByTypes['data-component'].length).toBe(4);
      expect(updateEventsByTypes['location'].length).toBe(12);
      expect(updateEventsByTypes['attack-pattern'].length).toBe(3);
      expect(updateEventsByTypes['feedback'].length).toBe(1);
      expect(updateEventsByTypes['course-of-action'].length).toBe(3);
      expect(updateEventsByTypes['data-source'].length).toBe(1);
      expect(updateEventsByTypes['external-reference'].length).toBe(1);
      expect(updateEventsByTypes['grouping'].length).toBe(3);
      expect(updateEventsByTypes['incident'].length).toBe(3);
      expect(updateEventsByTypes['indicator'].length).toBe(4);
      expect(updateEventsByTypes['label'].length).toBe(1);
      expect(updateEventsByTypes['malware-analysis'].length).toBe(3);
      expect(updateEventsByTypes['note'].length).toBe(3);
      expect(updateEventsByTypes['opinion'].length).toBe(6);
      expect(updateEventsByTypes['report'].length).toBe(12);
      expect(updateEventsByTypes['ipv4-addr'].length).toBe(3);
      expect(updateEventsByTypes['tool'].length).toBe(7);
      expect(updateEventsByTypes['sighting'].length).toBe(4);
      expect(updateEventsByTypes['threat-actor'].length).toBe(17);
      expect(updateEventsByTypes['vocabulary'].length).toBe(3);
      expect(updateEventsByTypes['vulnerability'].length).toBe(3);
      expect(updateEvents.length).toBe(150);
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
      expect(deleteEvents.length).toBe(131);
      // const deleteEventsByTypes = R.groupBy((e) => e.data.data.type, deleteEvents);
      for (let delIndex = 0; delIndex < deleteEvents.length; delIndex += 1) {
        const { data: insideData, origin, type } = deleteEvents[delIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      // 04 - CHECK MERGE EVENTS
      const mergeEvents = events.filter((e) => e.type === EVENT_TYPE_MERGE);
      expect(mergeEvents.length).toBe(8);
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
