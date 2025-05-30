/* eslint-disable @typescript-eslint/dot-notation */
import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { FIVE_MINUTES } from '../../utils/testQuery';
import { checkStreamData, checkStreamGenericContent, fetchStreamEvents, } from '../../utils/testStream';
import { PORT } from '../../../src/config/conf';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../../../src/database/utils';
import { writeTestDataToFile } from '../../utils/testOutput';
import { VOCABULARY_NUMBERS } from '../../04-sync/sync-utils';
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
      // Check the number of events
      // 01 - CHECK CREATE EVENTS.
      const createEvents = events.filter((e) => e.type === EVENT_TYPE_CREATE);
      // Check some events count
      const createEventsByTypes = R.groupBy((e) => e.data.data.type, createEvents);
      dumpEventByTypeToFile('create', createEventsByTypes);
      expect(createEventsByTypes.artifact.length).toBe(testCreatedCounter.artifact);
      expect(createEventsByTypes['attack-pattern'].length).toBe(testCreatedCounter['attack-pattern']);
      expect(createEventsByTypes['case-incident'].length).toBe(testCreatedCounter['case-incident']);
      expect(createEventsByTypes['case-rfi'].length).toBe(testCreatedCounter['case-rfi']);
      expect(createEventsByTypes.campaign.length).toBe(testCreatedCounter.campaign);
      expect(createEventsByTypes['course-of-action'].length).toBe(testCreatedCounter['course-of-action']);
      expect(createEventsByTypes.credential.length).toBe(testCreatedCounter.credential);
      expect(createEventsByTypes['data-component'].length).toBe(testCreatedCounter['data-component']);
      expect(createEventsByTypes['data-source'].length).toBe(testCreatedCounter['data-source']);
      expect(createEventsByTypes['domain-name'].length).toBe(testCreatedCounter['domain-name']);
      expect(createEventsByTypes['email-addr'].length).toBe(testCreatedCounter['email-addr']);
      expect(createEventsByTypes['external-reference'].length).toBe(testCreatedCounter['external-reference']);
      expect(createEventsByTypes.feedback.length).toBe(testCreatedCounter.feedback);
      expect(createEventsByTypes.file.length).toBe(testCreatedCounter.file);
      expect(createEventsByTypes.grouping.length).toBe(testCreatedCounter.grouping);
      expect(createEventsByTypes.identity.length).toBe(testCreatedCounter.identity);
      expect(createEventsByTypes.incident.length).toBe(testCreatedCounter.incident);
      expect(createEventsByTypes.indicator.length).toBe(testCreatedCounter.indicator);
      expect(createEventsByTypes['internal-relationship'].length).toBe(testCreatedCounter['internal-relationship']);
      expect(createEventsByTypes['ipv4-addr'].length).toBe(testCreatedCounter['ipv4-addr']);
      expect(createEventsByTypes['kill-chain-phase'].length).toBe(testCreatedCounter['kill-chain-phase']);
      expect(createEventsByTypes.label.length).toBe(testCreatedCounter.label);
      expect(createEventsByTypes.location.length).toBe(testCreatedCounter.location);
      expect(createEventsByTypes.malware.length).toBe(testCreatedCounter.malware);
      expect(createEventsByTypes['marking-definition'].length).toBe(testCreatedCounter['marking-definition']);
      expect(createEventsByTypes['network-traffic'].length).toBe(testCreatedCounter['network-traffic']);
      expect(createEventsByTypes.note.length).toBe(testCreatedCounter.note);
      expect(createEventsByTypes['observed-data'].length).toBe(testCreatedCounter['observed-data']);
      expect(createEventsByTypes.opinion.length).toBe(testCreatedCounter.opinion);
      expect(createEventsByTypes.persona.length).toBe(testCreatedCounter.persona);
      expect(createEventsByTypes.relationship.length).toBe(testCreatedCounter.relationship);
      expect(createEventsByTypes.report.length).toBe(testCreatedCounter.report);
      expect(createEventsByTypes.sighting.length).toBe(testCreatedCounter.sighting);
      expect(createEventsByTypes.software.length).toBe(testCreatedCounter.software);
      expect(createEventsByTypes['threat-actor'].length).toBe(testCreatedCounter['threat-actor']);
      expect(createEventsByTypes.tool.length).toBe(testCreatedCounter.tool);
      expect(createEventsByTypes['tracking-number'].length).toBe(testCreatedCounter['tracking-number']);
      expect(createEventsByTypes.vocabulary.length).toBe(VOCABULARY_NUMBERS);
      expect(createEventsByTypes.vulnerability.length).toBe(testCreatedCounter.vulnerability);

      expect(createEvents.length).toBe(doTotal(testCreatedCounter));
      for (let createIndex = 0; createIndex < createEvents.length; createIndex += 1) {
        const { data: insideData, origin, type } = createEvents[createIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      // 02 - CHECK UPDATE EVENTS.
      const updateEvents = events.filter((e) => e.type === EVENT_TYPE_UPDATE);
      const updateEventsByTypes = R.groupBy((e) => e.data.data.type, updateEvents);
      dumpEventByTypeToFile('update', updateEventsByTypes);
      expect(updateEventsByTypes['marking-definition'].length).toBe(2);
      expect(updateEventsByTypes['campaign'].length).toBe(7);
      expect(updateEventsByTypes['relationship'].length).toBe(8);
      expect(updateEventsByTypes['identity'].length).toBe(23);
      expect(updateEventsByTypes['malware'].length).toBe(20);
      expect(updateEventsByTypes['intrusion-set'].length).toBe(4);
      expect(updateEventsByTypes['data-component'].length).toBe(4);
      expect(updateEventsByTypes['location'].length).toBe(14);
      expect(updateEventsByTypes['attack-pattern'].length).toBe(3);
      expect(updateEventsByTypes['feedback'].length).toBe(1);
      expect(updateEventsByTypes['course-of-action'].length).toBe(3);
      expect(updateEventsByTypes['data-source'].length).toBe(1);
      expect(updateEventsByTypes['external-reference'].length).toBe(1);
      expect(updateEventsByTypes['grouping'].length).toBe(3);
      expect(updateEventsByTypes['incident'].length).toBe(3);
      expect(updateEventsByTypes['indicator'].length).toBe(6);
      expect(updateEventsByTypes['label'].length).toBe(1);
      expect(updateEventsByTypes['malware-analysis'].length).toBe(3);
      expect(updateEventsByTypes['note'].length).toBe(3);
      expect(updateEventsByTypes['opinion'].length).toBe(6);
      expect(updateEventsByTypes['report'].length).toBe(19);
      expect(updateEventsByTypes['ipv4-addr'].length).toBe(4);
      expect(updateEventsByTypes['tool'].length).toBe(9);
      expect(updateEventsByTypes['sighting'].length).toBe(4);
      expect(updateEventsByTypes['threat-actor'].length).toBe(17);
      expect(updateEventsByTypes['vocabulary'].length).toBe(3);
      expect(updateEventsByTypes['vulnerability'].length).toBe(3);
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
      const deleteEvents = events.filter((e) => e.type === EVENT_TYPE_DELETE);
      const deleteEventsByTypes = R.groupBy((e) => e.data.data.type, deleteEvents);
      dumpEventByTypeToFile('delete', deleteEventsByTypes);
      expect(deleteEvents.length).toBe(doTotal(testDeletedCounter));
      // const deleteEventsByTypes = R.groupBy((e) => e.data.data.type, deleteEvents);
      for (let delIndex = 0; delIndex < deleteEvents.length; delIndex += 1) {
        const { data: insideData, origin, type } = deleteEvents[delIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      // 04 - CHECK MERGE EVENTS
      const mergeEvents = events.filter((e) => e.type === EVENT_TYPE_MERGE);
      const mergeEventsByTypes = R.groupBy((e) => e.data.data.type, mergeEvents);
      dumpEventByTypeToFile('merge', mergeEventsByTypes);
      expect(mergeEventsByTypes['threat-actor'].length).toBe(testMergedCounter['threat-actor']);
      expect(mergeEventsByTypes.identity.length).toBe(testMergedCounter.identity);
      expect(mergeEventsByTypes.report.length).toBe(testMergedCounter.report);
      expect(mergeEventsByTypes.file.length).toBe(testMergedCounter.file);
      expect(mergeEventsByTypes.artifact.length).toBe(testMergedCounter.artifact);
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
