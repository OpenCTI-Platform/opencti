import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { ADMIN_USER, FIVE_MINUTES, SYNC_LIVE_EVENTS_SIZE, testContext } from '../../utils/testQuery';
import { checkInstanceDiff, checkStreamGenericContent, fetchStreamEvents } from '../../utils/testStream';
import { storeLoadByIdWithRefs } from '../../../src/database/middleware';
import { elAggregationCount } from '../../../src/database/engine';
import { convertEntityTypeToStixType } from '../../../src/schema/schemaUtils';
import { convertStoreToStix } from '../../../src/database/stix-converter';
import { utcDate } from '../../../src/utils/format';
import { PORT } from '../../../src/config/conf';
import httpServer from '../../../src/http/httpServer';
import { READ_DATA_INDICES } from '../../../src/database/utils';

describe('Live streams tests', () => {
  beforeAll(async () => {
    await httpServer.start();
  });
  afterAll(async () => {
    await httpServer.shutdown();
  });

  const getElementsCounting = async () => {
    const data = {};
    const stixCoreAgg = await elAggregationCount(testContext, ADMIN_USER, READ_DATA_INDICES, { types: ['Stix-Object'], field: 'entity_type' });
    for (let index = 0; index < stixCoreAgg.length; index += 1) {
      const { label, value } = stixCoreAgg[index];
      const key = convertEntityTypeToStixType(label);
      if (data[key]) {
        data[key] += value;
      } else {
        data[key] = value;
      }
    }
    const stixCoreRelAgg = await elAggregationCount(testContext, ADMIN_USER, READ_DATA_INDICES, { types: ['stix-core-relationship'], field: 'entity_type' });
    data.relationship = R.sum(stixCoreRelAgg.map((r) => r.value));
    const stixSightingRelAgg = await elAggregationCount(testContext, ADMIN_USER, READ_DATA_INDICES, { types: ['stix-sighting-relationship'], field: 'entity_type' });
    data.sighting = R.sum(stixSightingRelAgg.map((r) => r.value));
    return data;
  };
  const checkResultCounting = async (events) => {
    const byType = R.groupBy((e) => e.data.data.type, events);
    const elementsCounting = await getElementsCounting();
    const keys = Object.keys(byType);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const number = byType[key].length;
      const dbNumber = elementsCounting[key];
      expect(dbNumber).toBeDefined();
      expect(number === dbNumber).toBeTruthy();
    }
  };

  it(
    'Should consume init live stream',
    async () => {
      // Check the stream rebuild
      const report = await storeLoadByIdWithRefs(testContext, ADMIN_USER, 'report--f2b63e80-b523-4747-a069-35c002c690db');
      const stixReport = convertStoreToStix(report);
      const now = utcDate().toISOString();
      const events = await fetchStreamEvents(`http://localhost:${PORT}/stream/live?from=0&recover=${now}`);
      expect(events.length).toBe(SYNC_LIVE_EVENTS_SIZE);
      await checkResultCounting(events);
      for (let index = 0; index < events.length; index += 1) {
        const { data: insideData, origin, type } = events[index];
        expect(origin).toBeDefined();
        checkStreamGenericContent(type, insideData);
      }
      // Check report rebuild consistency
      const reportEvents = events.filter((e) => report.standard_id === e.data.data.id);
      expect(reportEvents.length).toBe(1);
      const stixInstance = R.head(reportEvents).data.data;
      const diffElements = await checkInstanceDiff(stixReport, stixInstance);
      expect(diffElements.length).toBe(0);
    },
    FIVE_MINUTES
  );
});
