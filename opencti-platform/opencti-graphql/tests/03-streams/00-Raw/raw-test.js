import { validate as isUuid } from 'uuid';
import * as R from 'ramda';
import moment from 'moment';
import { ADMIN_USER, FIVE_MINUTES } from '../../utils/testQuery';
import { shutdownModules, startModules } from '../../../src/modules';
import { fetchStreamEvents } from '../../utils/testStream';
import { isStixId } from '../../../src/schema/schemaUtils';
import { UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE } from '../../../src/database/utils';
import { isMultipleAttribute } from '../../../src/schema/fieldDataAdapter';
import { isStixRelationship } from '../../../src/schema/stixRelationship';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_MERGE,
  EVENT_TYPE_UPDATE,
} from '../../../src/database/rabbitmq';
import { fullLoadById, internalLoadById } from '../../../src/database/middleware';
import { rebuildInstanceWithPatch } from '../../../src/utils/patch';
import { buildStixData } from '../../../src/database/stix';

const OPERATIONS = [UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE];

describe('Raw streams tests', () => {
  beforeAll(async () => {
    await startModules();
  });
  afterAll(async () => {
    await shutdownModules();
  });
  const checkStreamData = (type, data) => {
    expect(data.id).toBeDefined();
    expect(isStixId(data.id)).toBeTruthy();
    expect(data.x_opencti_id).toBeDefined();
    expect(isUuid(data.x_opencti_id)).toBeTruthy();
    expect(data.type).toBeDefined();
    if (type === EVENT_TYPE_CREATE) {
      expect(data.created_at).toBeDefined();
      expect(moment(data.created_at).isValid()).toBeTruthy();
      expect(data.updated_at).toBeDefined();
      expect(moment(data.updated_at).isValid()).toBeTruthy();
    }
    if (data.type === 'relationship') {
      expect(data.relationship_type).toBeDefined();
      expect(isStixRelationship(data.relationship_type)).toBeTruthy();
      expect(data.source_ref).toBeDefined();
      expect(isStixId(data.source_ref)).toBeTruthy();
      expect(data.x_opencti_source_ref).toBeDefined();
      expect(isUuid(data.x_opencti_source_ref)).toBeTruthy();
      expect(data.target_ref).toBeDefined();
      expect(isStixId(data.target_ref)).toBeTruthy();
      expect(data.x_opencti_target_ref).toBeDefined();
      expect(isUuid(data.x_opencti_target_ref)).toBeTruthy();
    }
    if (data.x_opencti_stix_ids) {
      data.x_opencti_stix_ids.forEach((m) => {
        expect(isStixId(m)).toBeTruthy();
      });
    }
  };
  const checkStreamGenericContent = (type, dataEvent) => {
    const { data, markings, message } = dataEvent;
    expect(markings).toBeDefined();
    if (markings.length > 0) {
      markings.forEach((m) => {
        expect(isUuid(m)).toBeTruthy();
      });
    }
    expect(message).not.toBeNull();
    checkStreamData(type, data);
  };
  // We need to check the event format to be sure that everything is setup correctly
  // eslint-disable-next-line prettier/prettier
  it('Should stream correctly formatted', async () => {
      // Read all events from the beginning.
      const events = await fetchStreamEvents('http://localhost:4000/stream', '0');
      // Check the number of events
      expect(events.length).toBe(588);
      // 01 - CHECK CREATE EVENTS
      const createEvents = events.filter((e) => e.type === EVENT_TYPE_CREATE);
      expect(createEvents.length).toBe(262);
      for (let createIndex = 0; createIndex < createEvents.length; createIndex += 1) {
        const { data: insideData, origin, type } = createEvents[createIndex];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      // 02 - CHECK UPDATE EVENTS
      const updateEvents = events.filter((e) => e.type === EVENT_TYPE_UPDATE);
      expect(updateEvents.length).toBe(286);
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
              const isMultiple = opKey.endsWith('_refs') || isMultipleAttribute(opKey);
              expect(isMultiple).toBeTruthy();
              const val = elementOperations[opKey];
              expect(Array.isArray(val)).toBeTruthy();
            });
          }
          if (key === UPDATE_OPERATION_REPLACE) {
            const elementOperations = data.x_opencti_patch[UPDATE_OPERATION_REPLACE];
            const opValues = Object.values(elementOperations);
            opValues.forEach((e) => {
              expect(e.current).toBeDefined();
              expect(e.previous).toBeDefined();
              const isArrayValue = Array.isArray(e.current);
              if (isArrayValue) {
                expect(Array.isArray(e.previous)).toBeTruthy();
                expect(e.current.sort()).not.toEqual(e.previous.sort());
              } else {
                expect(e.current).not.toEqual(e.previous);
              }
            });
          }
        });
      }
      // 03 - CHECK DELETE EVENTS
      const deleteEvents = events.filter((e) => e.type === EVENT_TYPE_DELETE);
      expect(deleteEvents.length).toBe(37);
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
        expect(data.x_opencti_sources).toBeDefined();
        expect(data.x_opencti_sources.length > 0).toBeTruthy();
        for (let sourceIndex = 0; sourceIndex < data.x_opencti_sources.length; sourceIndex += 1) {
          const source = data.x_opencti_sources[sourceIndex];
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
      const events = await fetchStreamEvents('http://localhost:4000/stream', '0');
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
      const attributes = Object.keys(stixReport);
      const diffElements = [];
      for (let attrIndex = 0; attrIndex < attributes.length; attrIndex += 1) {
        const attributeKey = attributes[attrIndex];
        if (attributeKey === 'revoked' || attributeKey === 'lang') {
          // Currently some attributes are valuated by default
        } else {
          const fetchAttr = stixReport[attributeKey];
          let rebuildAttr = stixInstance[attributeKey];
          if (attributeKey.endsWith('_ref')) {
            const data = await internalLoadById(ADMIN_USER, rebuildAttr);
            rebuildAttr = data.standard_id;
          }
          if (attributeKey.endsWith('_refs')) {
            const data = await Promise.all(rebuildAttr.map(async (r) => internalLoadById(ADMIN_USER, r)));
            rebuildAttr = data.map((r) => r.standard_id);
          }
          if (Array.isArray(fetchAttr)) {
            if (!R.equals(fetchAttr.sort(), rebuildAttr.sort())) {
              diffElements.push({ attributeKey, fetchAttr, rebuildAttr });
            }
          } else if (!R.equals(fetchAttr, rebuildAttr)) {
            diffElements.push({ attributeKey, fetchAttr, rebuildAttr });
          }
        }
      }
      expect(diffElements.length).toBe(0);
    },
    FIVE_MINUTES
  );
});
