import * as R from 'ramda';
import { ADMIN_USER, FIVE_MINUTES } from '../../utils/testQuery';
import { shutdownModules, startModules } from '../../../src/modules';
import {
  checkInstanceDiff,
  checkStreamData,
  checkStreamGenericContent,
  fetchStreamEvents,
} from '../../utils/testStream';
import { UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE } from '../../../src/database/utils';
import { isMultipleAttribute } from '../../../src/schema/fieldDataAdapter';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../../../src/database/amqp';
import { fullLoadById } from '../../../src/database/middleware';
import { rebuildInstanceWithPatch } from '../../../src/utils/patch';
import { buildStixData } from '../../../src/database/stix';
import { STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD } from '../../../src/schema/stixMetaRelationship';

const OPERATIONS = [UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE];

describe('Raw streams tests', () => {
  beforeAll(async () => {
    await startModules();
  });
  afterAll(async () => {
    await shutdownModules();
  });
  // We need to check the event format to be sure that everything is setup correctly
  // eslint-disable-next-line prettier/prettier
  it('Should stream correctly formatted', async () => {
      // Read all events from the beginning.
      const events = await fetchStreamEvents('http://localhost:4000/stream', { from: '0' });
      // const test = R.groupBy((e) => e.data.data.type, events);
      // Check the number of events
      expect(events.length).toBe(610);
      // 01 - CHECK CREATE EVENTS
      const createEvents = events.filter((e) => e.type === EVENT_TYPE_CREATE);
      expect(createEvents.length).toBe(290);
      // Check some events count
      const createEventsByTypes = R.groupBy((e) => e.data.data.type, createEvents);
      expect(createEventsByTypes['marking-definition'].length).toBe(7);
      expect(createEventsByTypes.label.length).toBe(15);
      expect(createEventsByTypes.identity.length).toBe(13);
      expect(createEventsByTypes.relationship.length).toBe(118);
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
      expect(updateEvents.length).toBe(280);
      const updateEventsByTypes = R.groupBy((e) => e.data.data.type, updateEvents);
      expect(updateEventsByTypes.report.length).toBe(182);
      for (let updateIndex = 0; updateIndex < updateEvents.length; updateIndex += 1) {
        const { data: insideData, origin, type } = updateEvents[updateIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
        // Test patch content
        const { data } = insideData;
        expect(data.x_opencti_patch).toBeDefined();
        const patchKeys = Object.keys(data.x_opencti_patch);
        expect(patchKeys.length > 0).toBeTruthy();
        expect(patchKeys.some((p) => OPERATIONS.includes(p))).toBeTruthy();
        patchKeys.forEach((key) => {
          if (key === UPDATE_OPERATION_ADD || key === UPDATE_OPERATION_REMOVE) {
            const elementOperations = data.x_opencti_patch[key];
            const opKeys = Object.keys(elementOperations);
            opKeys.forEach((opKey) => {
              const metaKey = STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD[opKey];
              const k = metaKey || opKey;
              const isMultiple = isMultipleAttribute(k);
              expect(isMultiple).toBeTruthy();
              const val = elementOperations[opKey];
              expect(Array.isArray(val)).toBeTruthy();
              if (metaKey) {
                for (let i = 0; i < val.length; i += 1) {
                  const metaElement = val[i];
                  expect(metaElement.value).toBeDefined();
                  expect(metaElement.x_opencti_id).toBeDefined();
                }
              }
            });
          }
          if (key === UPDATE_OPERATION_REPLACE) {
            const elementOperations = data.x_opencti_patch[UPDATE_OPERATION_REPLACE];
            const opEntries = Object.entries(elementOperations);
            opEntries.forEach(([keyElem, e]) => {
              expect(e.current).toBeDefined();
              expect(e.previous).toBeDefined();
              const isArrayValue = Array.isArray(e.current);
              if (isArrayValue) {
                expect(Array.isArray(e.previous)).toBeTruthy();
                expect(e.current.sort()).not.toEqual(e.previous.sort());
              } else {
                expect(e.current).not.toEqual(e.previous);
              }
              // Special check for standard id evolution
              if (keyElem === 'id') {
                expect(data.id).not.toEqual(e.current);
                expect(data.id).toEqual(e.previous);
              }
            });
          }
        });
      }
      // 03 - CHECK DELETE EVENTS
      const deleteEvents = events.filter((e) => e.type === EVENT_TYPE_DELETE);
      expect(deleteEvents.length).toBe(37);
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
        expect(origin).toBeDefined();
        expect(data.x_opencti_patch).toBeDefined();
        expect(data.x_opencti_context).toBeDefined();
        expect(data.x_opencti_context.sources).toBeDefined();
        expect(data.x_opencti_context.sources.length > 0).toBeTruthy();
        for (let sourceIndex = 0; sourceIndex < data.x_opencti_context.sources.length; sourceIndex += 1) {
          const source = data.x_opencti_context.sources[sourceIndex];
          checkStreamData(EVENT_TYPE_MERGE, source);
        }
      }
    },
    FIVE_MINUTES
  );
  // Based on all events of a specific element, can we reconstruct the final state correctly?
  // eslint-disable-next-line prettier/prettier
  it('Should events rebuild succeed', async () => {
      const report = await fullLoadById(ADMIN_USER, 'report--f2b63e80-b523-4747-a069-35c002c690db');
      const stixReport = buildStixData(report);
      const events = await fetchStreamEvents('http://localhost:4000/stream', { from: '0' });
      const reportEvents = events.filter((e) => report.standard_id === e.data.data.id);
      expect(reportEvents.length).toBe(154);
      const createEvents = reportEvents.filter((e) => e.type === EVENT_TYPE_CREATE);
      expect(createEvents.length).toBe(1);
      const updateEvents = reportEvents.filter((e) => e.type === EVENT_TYPE_UPDATE);
      expect(updateEvents.length).toBe(153);
      // Rebuild the data
      let stixInstance = R.head(createEvents).data.data;
      for (let index = 0; index < updateEvents.length; index += 1) {
        const { x_opencti_patch: patch } = updateEvents[index].data.data;
        stixInstance = rebuildInstanceWithPatch(stixInstance, patch);
      }
      // Check
      const diffElements = await checkInstanceDiff(stixReport, stixInstance);
      expect(diffElements.length).toBe(0);
    },
    FIVE_MINUTES
  );
  // Based on all events of a specific element, can we reconstruct the final state correctly?
  // eslint-disable-next-line prettier/prettier
  it('Should events context available', async () => {
      const events = await fetchStreamEvents('http://localhost:4000/stream', { from: '0' });
      const contextWithDeletionEvents = events.filter(
        (e) =>
          (e.data.data.x_opencti_context?.deletions || []).length > 0 ||
          (e.data.data.x_opencti_context?.sources || []).length > 0
      );
      const deletions = R.flatten(
        contextWithDeletionEvents.map((e) => [
          ...(e.data.data.x_opencti_context?.deletions || []),
          ...(e.data.data.x_opencti_context?.sources || []),
        ])
      );
      const byTypes = R.groupBy((e) => e.type, deletions);
      expect(byTypes.relationship.length).toBe(6); // Due to merge and sub deletions
      expect(byTypes['threat-actor'].length).toBe(6); // Merge of threat actors in test
      expect(byTypes.file.length).toBe(2); // Merge of files in test
    },
    FIVE_MINUTES
  );
});
