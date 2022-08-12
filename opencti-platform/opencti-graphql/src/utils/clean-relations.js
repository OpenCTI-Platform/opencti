import * as R from 'ramda';
import { ES_IGNORE_THROTTLED, elRawSearch } from '../database/engine';
import { logApp } from '../config/conf';
import { ABSTRACT_BASIC_RELATIONSHIP } from '../schema/general';
import { deleteElementById } from '../database/middleware';
import { READ_DATA_INDICES, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { SYSTEM_USER } from './access';

const average = (arr) => arr.reduce((p, c) => p + c, 0) / arr.length;
const computeMissingRelationsForType = async (relationType) => {
  const paginationCount = 500;
  const relationsToTakeCare = [];
  let hasNextPage = true;
  let searchAfter = '';
  let counter = 0;
  let timeSpent = 0;
  const timesSpent = [];
  let lastRun = new Date();
  while (hasNextPage) {
    let body = {
      size: paginationCount,
      sort: { 'internal_id.keyword': 'asc' },
      query: {
        bool: {
          should: [{ match_phrase: { entity_type: relationType } }, { match_phrase: { parent_types: relationType } }],
          minimum_should_match: 1,
        },
      },
    };
    if (searchAfter) {
      body = { ...body, search_after: [searchAfter] };
    }
    const query = {
      index: READ_RELATIONSHIPS_INDICES,
      ignore_throttled: ES_IGNORE_THROTTLED,
      _source_includes: ['internal_id', 'entity_type', 'connections'],
      track_total_hits: true,
      body,
    };
    const queryRelations = await elRawSearch(query);
    const { hits, total: { value: valTotal } } = queryRelations.hits;
    if (hits.length === 0) {
      hasNextPage = false;
    } else {
      const lastHit = R.last(hits);
      searchAfter = R.head(lastHit.sort);
      counter += hits.length;
      const connectionIds = R.uniq(R.flatten(hits.map((h) => h._source.connections.map((c) => c.internal_id))));
      const findTerms = connectionIds.map((c) => {
        return { term: { 'internal_id.keyword': c } };
      });
      const findQuery = {
        index: READ_DATA_INDICES,
        ignore_throttled: ES_IGNORE_THROTTLED,
        size: 2000,
        _source_includes: 'internal_id',
        body: {
          query: {
            bool: {
              should: findTerms,
              minimum_should_match: 1,
            },
          },
        },
      };
      const data = await elRawSearch(findQuery);
      const resolvedConns = data.hits.hits.map((i) => i._source);
      const resolvedIds = resolvedConns.map((r) => r.internal_id);
      const relationsToRemove = hits
        .map((h) => h._source)
        .filter((s) => {
          return !R.all(
            (a) => resolvedIds.includes(a),
            s.connections.map((c) => c.internal_id)
          );
        });
      relationsToTakeCare.push(...relationsToRemove);
      const timeForRun = new Date().getTime() - lastRun.getTime();
      timesSpent.push(timeForRun);
      timeSpent += timeForRun;
      const totalNumberOfIteration = valTotal / paginationCount;
      const totalEstimation = average(timesSpent) * totalNumberOfIteration;
      const remaining = (totalEstimation - timeSpent) / 1000 / 60;
      const findNumber = relationsToTakeCare.length;
      const remainTimeMin = remaining.toFixed(2);
      const message = `[MIGRATION] Scanning ${relationType}: ${counter}/${valTotal} (Found ${findNumber} to clear) -- Estimate remaining ${remainTimeMin} min`;
      logApp.info(message);
      lastRun = new Date();
    }
  }
  return relationsToTakeCare;
};
const getMissingRelations = async () => {
  const data = await computeMissingRelationsForType(ABSTRACT_BASIC_RELATIONSHIP);
  return R.flatten(data);
};
// eslint-disable-next-line import/prefer-default-export
export const cleanInconsistentRelations = async () => {
  // Fix missing deleted data
  // In case of relation to relation, some deletion was not executed.
  // For each relations of the platform we need to check if the from and the to are available.
  logApp.info('[TOOLS] Starting script to fix missing deletion');
  const relations = await getMissingRelations();
  for (let index = 0; index < relations.length; index += 1) {
    const relation = relations[index];
    await deleteElementById(SYSTEM_USER, relation.internal_id, relation.entity_type);
  }
  logApp.info('[TOOLS] Fix missing script migration done');
};
