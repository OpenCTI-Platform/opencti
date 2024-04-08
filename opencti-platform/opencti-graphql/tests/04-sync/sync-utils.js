import { expect } from 'vitest';
import { elAggregationCount } from '../../src/database/engine';
import { ADMIN_USER, createHttpClient, executeExternalQuery, testContext } from '../utils/testQuery';
import { READ_DATA_INDICES } from '../../src/database/utils';
import { storeLoadByIdWithRefs } from '../../src/database/middleware';
import { convertStoreToStix } from '../../src/database/stix-converter';
import { checkInstanceDiff } from '../utils/testStream';
import { logAudit } from '../../src/config/conf';
import { ENTITY_TYPE_DELETE_OPERATION } from '../../src/modules/deleteOperation/deleteOperation-types';

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

export const UPLOADED_FILE_SIZE = 42204;

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
  expect(objectMap.get('Indicator')).toEqual(28);
  expect(objectMap.get('Malware')).toEqual(27);
  expect(objectMap.get('Label')).toEqual(13);
  expect(objectMap.get('Vocabulary')).toEqual(342);
  // Relations
  const initRelationAggregation = await elAggregationCount(testContext, ADMIN_USER, READ_DATA_INDICES, { types: ['stix-relationship'], field: 'entity_type', filters: filterOutDeleteOperationRefs });
  const relMap = new Map(initRelationAggregation.map((i) => [i.label, i.value]));
  expect(relMap.get('Object')).toEqual(191);
  expect(relMap.get('Indicates')).toEqual(59);
  expect(relMap.get('Uses')).toEqual(28);
  // Report content
  const initReport = await storeLoadByIdWithRefs(testContext, ADMIN_USER, 'report--f2b63e80-b523-4747-a069-35c002c690db');
  const initStixReport = convertStoreToStix(initReport);
  return { objectMap, relMap, initStixReport };
};
export const checkMapConsistency = (before, after) => {
  after.forEach((value, key) => {
    const compareValue = before.get(key);
    expect(`${key} - ${value}`).toEqual(`${key} - ${compareValue}`);
  });
};
export const checkPostSyncContent = async (remoteUri, objectMap, relMap, initStixReport) => {
  const client = createHttpClient();
  const data = await executeExternalQuery(client, remoteUri, STAT_QUERY);
  const { objects, relationships } = data.about.debugStats;
  const syncObjectMap = new Map(objects.map((i) => [i.label, i.value]));
  const syncRelMap = new Map(relationships.map((i) => [i.label, i.value]));
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
    logAudit.info(JSON.stringify(diffElements));
  }
  expect(diffElements.length).toBe(0);
};
