import * as R from 'ramda';
import { FIVE_MINUTES } from '../../utils/testQuery';
import { shutdownModules, startModules } from '../../../src/modules';
import {
  checkStreamData,
  checkStreamGenericContent,
  fetchStreamEvents,
} from '../../utils/testStream';
import { UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE } from '../../../src/database/utils';
import { isMultipleAttribute } from '../../../src/schema/fieldDataAdapter';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_MERGE,
  EVENT_TYPE_UPDATE,
} from '../../../src/database/rabbitmq';
import { STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD } from '../../../src/schema/stixMetaRelationship';
import { STIX_EXT_OCTI } from '../../../src/types/stix-extensions';

const OPERATIONS = [UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE];

describe('Raw streams tests', () => {
  // beforeAll(async () => {
  //   await startModules();
  // });
  // afterAll(async () => {
  //   await shutdownModules();
  // });

  // We need to check the event format to be sure that everything is setup correctly
  it(
    'Should stream correctly formatted',
    async () => {
      // Read all events from the beginning.
      const events = await fetchStreamEvents('http://localhost:4000/stream', { from: '0' });
      // Check the number of events
      expect(events.length).toBe(425);
      // 01 - CHECK CREATE EVENTS
      const createEvents = events.filter((e) => e.type === EVENT_TYPE_CREATE);
      expect(createEvents.length).toBe(293);
      // Check some events count
      const createEventsByTypes = R.groupBy((e) => e.data.data.type, createEvents);
      expect(createEventsByTypes['marking-definition'].length).toBe(7);
      expect(createEventsByTypes.label.length).toBe(15);
      expect(createEventsByTypes.identity.length).toBe(13);
      expect(createEventsByTypes.relationship.length).toBe(119);
      expect(createEventsByTypes.indicator.length).toBe(30);
      expect(createEventsByTypes['attack-pattern'].length).toBe(6);
      expect(createEventsByTypes.report.length).toBe(3);
      expect(createEventsByTypes.tool.length).toBe(2);
      expect(createEventsByTypes.vulnerability.length).toBe(7);
      for (let createIndex = 0; createIndex < createEvents.length; createIndex += 1) {
        const { data: insideData, origin, type } = createEvents[createIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      // 02 - CHECK UPDATE EVENTS
      const updateEvents = events.filter((e) => e.type === EVENT_TYPE_UPDATE);
      expect(updateEvents.length).toBe(90);
      const updateEventsByTypes = R.groupBy((e) => e.data.data.type, updateEvents);
      expect(updateEventsByTypes.report.length).toBe(3);
      for (let updateIndex = 0; updateIndex < updateEvents.length; updateIndex += 1) {
        const { data: insideData, origin, type } = updateEvents[updateIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
        // Test patch content
        const { data } = insideData;
        const { event_patch } = data.extensions[STIX_EXT_OCTI];
        expect(event_patch).toBeDefined();
        const patchKeys = Object.keys(event_patch);
        expect(patchKeys.length > 0).toBeTruthy();
        expect(patchKeys.some((p) => OPERATIONS.includes(p))).toBeTruthy();
        patchKeys.forEach((key) => {
          if (key === UPDATE_OPERATION_ADD || key === UPDATE_OPERATION_REMOVE) {
            const elementOperations = event_patch[key];
            const opKeys = Object.keys(elementOperations);
            opKeys.forEach((opKey) => {
              const metaKey = STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD[opKey];
              const k = metaKey || opKey;
              if (k !== 'extensions') {
                const isMultiple = isMultipleAttribute(k);
                expect(isMultiple).toBeTruthy();
                const val = elementOperations[opKey];
                expect(Array.isArray(val)).toBeTruthy();
                if (metaKey) {
                  for (let i = 0; i < val.length; i += 1) {
                    const metaElement = val[i];
                    expect(metaElement).toBeDefined();
                  }
                }
              }
            });
          }
          if (key === UPDATE_OPERATION_REPLACE) {
            const elementOperations = event_patch[UPDATE_OPERATION_REPLACE];
            const opEntries = Object.entries(elementOperations);
            opEntries.forEach(([, e]) => {
              expect(e === null || e !== undefined).toBeTruthy();
            });
          }
        });
      }
      // 03 - CHECK DELETE EVENTS
      const deleteEvents = events.filter((e) => e.type === EVENT_TYPE_DELETE);
      expect(deleteEvents.length).toBe(39);
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
        const { data } = insideData;
        console.log('origin', origin);
        expect(origin).toBeDefined();
        const octiExt = data.extensions[STIX_EXT_OCTI];
        console.log('octiExt', octiExt);
        expect(octiExt.event_patch).toBeDefined();
        expect(octiExt.event_dependencies).toBeDefined();
        expect(octiExt.event_dependencies.sources).toBeDefined();
        expect(octiExt.event_dependencies.sources.length > 0).toBeTruthy();
        for (let sourceIndex = 0; sourceIndex < octiExt.event_dependencies.sources.length; sourceIndex += 1) {
          const source = octiExt.event_dependencies.sources[sourceIndex];
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
      const events = await fetchStreamEvents('http://localhost:4000/stream', { from: '0' });
      const contextWithDeletionEvents = events.filter(
        (e) => {
          const { event_dependencies } = e.data.data.extensions[STIX_EXT_OCTI];
          return (event_dependencies?.deletions || []).length > 0 || (event_dependencies?.sources || []).length > 0;
        }
      );
      const deletions = R.flatten(
        contextWithDeletionEvents.map((e) => {
          const { event_dependencies } = e.data.data.extensions[STIX_EXT_OCTI];
          return [...(event_dependencies?.deletions || []), ...(event_dependencies?.sources || [])];
        })
      );
      const byTypes = R.groupBy((e) => e.type, deletions);
      expect(byTypes.relationship.length).toBe(7); // Due to merge and sub deletions
      expect(byTypes['threat-actor'].length).toBe(6); // Merge of threat actors in test
      expect(byTypes.file.length).toBe(2); // Merge of files in test
    },
    FIVE_MINUTES
  );
});
