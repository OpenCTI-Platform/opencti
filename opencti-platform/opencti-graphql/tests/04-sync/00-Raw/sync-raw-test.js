import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, ADMIN_API_TOKEN, API_URI, FIFTEEN_MINUTES, PYTHON_PATH, queryAsAdmin, RAW_EVENTS_SIZE, SYNC_RAW_START_REMOTE_URI, testContext } from '../../utils/testQuery';
import { execChildPython } from '../../../src/python/pythonBridge';
import { checkPostSyncContent, checkPreSyncContent } from '../sync-utils';
import { elAggregationCount } from '../../../src/database/engine';
import { READ_DATA_INDICES } from '../../../src/database/utils';

const LIST_QUERY = gql`
  query vocabularies(
    $category: VocabularyCategory
    $first: Int
    $after: ID
    $orderBy: VocabularyOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    vocabularies(
      category: $category
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

describe('Database sync raw', () => {
  it(
    'Should python raw sync succeed',
    async () => {
      const queryResultBefore = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 350 } });

      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      // Sync
      const syncOpts = [API_URI, ADMIN_API_TOKEN, SYNC_RAW_START_REMOTE_URI, ADMIN_API_TOKEN, RAW_EVENTS_SIZE, '0', 'None'];
      const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_synchronizer.py', syncOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');

      const queryResultAfter = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 350 } });

      const vocabBefore = queryResultBefore.data.vocabularies.edges.map((e) => e.node);
      const vocabAfter = queryResultAfter.data.vocabularies.edges.map((e) => e.node);

      const vocabRemoved = [];
      vocabBefore.forEach((vb) => {
        const found = vocabAfter.find((va) => va.id === vb.id) !== undefined;
        if (!found) vocabRemoved.push(vb);
      });

      const vocabAdded = [];
      vocabAfter.forEach((va) => {
        const found = vocabBefore.find((vb) => vb.id === va.id) !== undefined;
        if (!found) vocabAdded.push(va);
      });

      expect(vocabBefore.length).toEqual(vocabAfter.length);
      expect(vocabRemoved.map((v) => v.name)).toEqual([]);
      expect(vocabAdded.map((v) => v.name)).toEqual([]);

      expect(vocabBefore.length).toEqual(342);

      const counters = await elAggregationCount(testContext, ADMIN_USER, READ_DATA_INDICES, { types: ['Stix-Object'], field: 'entity_type' });
      const countersMap = new Map(counters.map((i) => [i.label, i.value]));
      expect(countersMap.get('Indicator')).toEqual(28);
      expect(countersMap.get('Malware')).toEqual(27);
      expect(countersMap.get('Label')).toEqual(13);
      expect(countersMap.get('Vocabulary')).toEqual(342);

      // Post check
      await checkPostSyncContent(SYNC_RAW_START_REMOTE_URI, objectMap, relMap, initStixReport);
    },
    FIFTEEN_MINUTES
  );
});
