import { expect } from 'vitest';
import { createReadStream } from 'node:fs';
import { elAggregationCount } from '../../src/database/engine';
import { ADMIN_USER, createHttpClient, DATA_FILE_TEST, executeExternalQuery, FIVE_MINUTES, testContext } from '../utils/testQuery';
import { READ_DATA_INDICES, wait } from '../../src/database/utils';
import { storeLoadByIdWithRefs } from '../../src/database/middleware';
import { checkInstanceDiff } from '../utils/testStream';
import conf, { logApp } from '../../src/config/conf';
import { ENTITY_TYPE_DELETE_OPERATION } from '../../src/modules/deleteOperation/deleteOperation-types';

import { convertStoreToStix_2_1 } from '../../src/database/stix-2-1-converter';
import { SYSTEM_USER } from '../../src/utils/access';
import { stixCoreObjectImportPush } from '../../src/domain/stixCoreObject';

const STAT_QUERY = `query stats {
      about {
        debugStats {
          objects {
            label
            value
          }
          relationships {
            label
            value
          }
        }
      }
    }
  `;
export const REPORT_QUERY = `query report($id: String) {
      report(id: $id) {
        toStix
        importFiles {
          edges {
            node {
              id
              name
              size
            }
          }
        }
      }
    }
  `;
const STANDARD_LOADER_QUERY = `query standard($id: String!) {
      stixObjectOrStixRelationship(id: $id) {
        ... on StixObject {
          standard_id
        }
        ... on StixRelationship {
          standard_id
        }
      }
    }
  `;
export const SYNC_CREATION_QUERY = `mutation SynchronizerAdd($input: SynchronizerAddInput!) {
      synchronizerAdd(input: $input) {
        id
      }
    }
  `;
export const SYNC_START_QUERY = `mutation SynchronizerStart($id: ID!) {
      synchronizerStart(id: $id) {
        id
      }
    }
  `;

export const VOCABULARY_NUMBERS = 358;
export const INDICATOR_NUMBERS = 28;
export const MALWARE_NUMBERS = 27;
export const LABEL_NUMBERS = 13;
export const UPLOADED_FILE_SIZE = 44174;

const filterOutDeleteOperationRefs = {
  mode: 'and',
  filters: [{
    mode: 'or',
    key: 'elementWithTargetTypes',
    values: [ENTITY_TYPE_DELETE_OPERATION],
    operator: 'not_eq',
  }],
  filterGroups: [],
};

export const checkPreSyncContent = async () => {
  const initObjectAggregation = await elAggregationCount(testContext, ADMIN_USER, READ_DATA_INDICES, { types: ['Stix-Object'], field: 'entity_type' });
  const objectMap = new Map(initObjectAggregation.map((i) => [i.label, i.value]));
  expect(objectMap.get('Indicator')).toEqual(INDICATOR_NUMBERS);
  expect(objectMap.get('Malware')).toEqual(MALWARE_NUMBERS);
  expect(objectMap.get('Label')).toEqual(LABEL_NUMBERS);
  expect(objectMap.get('Vocabulary')).toEqual(VOCABULARY_NUMBERS);
  // Relations
  const initRelationAggregation = await elAggregationCount(testContext, ADMIN_USER, READ_DATA_INDICES, { types: ['stix-relationship'], field: 'entity_type', filters: filterOutDeleteOperationRefs });
  const relMap = new Map(initRelationAggregation.map((i) => [i.label, i.value]));
  expect(relMap.get('Object')).toEqual(191);
  expect(relMap.get('Indicates')).toEqual(59);
  expect(relMap.get('Uses')).toEqual(28);
  // Report content
  const initReport = await storeLoadByIdWithRefs(testContext, ADMIN_USER, 'report--f2b63e80-b523-4747-a069-35c002c690db');
  const initStixReport = convertStoreToStix_2_1(initReport);
  return { objectMap, relMap, initStixReport };
};
const computeMapDifferences = (before, after) => {
  const failedExpects = [];
  // Both sides: a type can be missing on either one
  new Set([...before.keys(), ...after.keys()]).forEach((key) => {
    const current = `${key} - ${after.get(key)}`;
    const expected = `${key} - ${before.get(key)}`;
    if (current !== expected) {
      failedExpects.push({ current, expected });
    }
  });
  return failedExpects;
};
export const checkMapConsistency = (before, after) => {
  const failedExpects = computeMapDifferences(before, after);
  expect(failedExpects.length, `checkMapConsistency failed ${JSON.stringify(failedExpects)}`).toEqual(0);
};
const fetchRemoteStats = async (client, remoteUri) => {
  const data = await executeExternalQuery(client, remoteUri, STAT_QUERY);
  const { objects, relationships } = data.about.debugStats;
  const syncObjectMap = new Map(objects.map((i) => [i.label, i.value]));
  const syncRelMap = new Map(relationships.map((i) => [i.label, i.value]));
  return { syncObjectMap, syncRelMap };
};

// The direct and backup/restore syncs check this file on their remote platform
export const uploadReportFile = async () => {
  const file = {
    createReadStream: () => createReadStream('./tests/data/DATA-TEST-STIX2_v2.json'),
    filename: DATA_FILE_TEST,
    mimetype: 'application/json',
  };
  await stixCoreObjectImportPush(testContext, SYSTEM_USER, 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7', file);
};

const POLL_INTERVAL = 5000;

// The sync instances boot while the first test files run (see ci-test-backend.yml)
export const waitForRemotePlatform = async (remoteUri, timeout = FIVE_MINUTES) => {
  const healthUrl = new URL(`health?health_access_key=${conf.get('app:health_access_key')}`, remoteUri);
  const deadline = Date.now() + timeout;
  let lastAnswer = 'no response';
  while (Date.now() < deadline) {
    // No response while still booting
    const response = await fetch(healthUrl).catch(() => undefined);
    if (response) {
      await response.body?.cancel();
      if (response.ok) {
        return;
      }
      if (response.status === 401) {
        throw new Error(`Remote platform ${remoteUri} rejects app:health_access_key`);
      }
      lastAnswer = `HTTP ${response.status}`;
    }
    await wait(POLL_INTERVAL);
  }
  throw new Error(`Remote platform ${remoteUri} is not healthy after ${timeout} ms (last answer: ${lastAnswer})`);
};

// Poll until the remote platform holds the same content, twice in a row so a transient match does not count.
// It never asserts: on timeout, checkPostSyncContent reports the remaining differences.
export const waitForRemoteSync = async (remoteUri, objectMap, relMap, isRemoteReady = async () => true, timeout = FIVE_MINUTES) => {
  const client = createHttpClient();
  const deadline = Date.now() + timeout;
  let consecutiveMatches = 0;
  while (Date.now() < deadline && consecutiveMatches < 2) {
    await wait(POLL_INTERVAL);
    try {
      const { syncObjectMap, syncRelMap } = await fetchRemoteStats(client, remoteUri);
      const isSameContent = computeMapDifferences(objectMap, syncObjectMap).length === 0
        && computeMapDifferences(relMap, syncRelMap).length === 0;
      consecutiveMatches = isSameContent && await isRemoteReady() ? consecutiveMatches + 1 : 0;
    } catch {
      consecutiveMatches = 0;
    }
  }
};
export const checkPostSyncContent = async (remoteUri, objectMap, relMap, initStixReport) => {
  const client = createHttpClient();
  const { syncObjectMap, syncRelMap } = await fetchRemoteStats(client, remoteUri);
  checkMapConsistency(objectMap, syncObjectMap);
  checkMapConsistency(relMap, syncRelMap);
  const reportData = await executeExternalQuery(client, remoteUri, REPORT_QUERY, {
    id: 'report--f2b63e80-b523-4747-a069-35c002c690db',
  });
  const stixReport = JSON.parse(reportData.report.toStix);
  const idLoader = async (context, user, id) => {
    const dataId = await executeExternalQuery(client, remoteUri, STANDARD_LOADER_QUERY, { id });
    return dataId.stixObjectOrStixRelationship;
  };
  const diffElements = await checkInstanceDiff(initStixReport, stixReport, idLoader);
  if (diffElements.length > 0) {
    logApp.info(JSON.stringify(diffElements));
  }
  expect(diffElements.length).toBe(0);
};
