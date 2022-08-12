import * as R from 'ramda';
import { ES_IGNORE_THROTTLED, elRawSearch } from '../database/engine';
import { READ_INDEX_STIX_CYBER_OBSERVABLES } from '../database/utils';
import { mergeEntities, patchAttribute } from '../database/middleware';
import { generateStandardId } from '../schema/identifier';
import { logApp } from '../config/conf';
import { SYSTEM_USER } from '../utils/access';

export const up = async (next) => {
  // region find duplicates
  const query = {
    index: READ_INDEX_STIX_CYBER_OBSERVABLES,
    ignore_throttled: ES_IGNORE_THROTTLED,
    body: {
      aggs: {
        url: {
          filter: { match: { entity_type: 'Url' } },
          aggs: {
            duplicateUri: {
              terms: {
                field: 'value.keyword',
                order: { _key: 'desc' },
                size: 10000,
                min_doc_count: 2,
              },
            },
          },
        },
      },
    },
  };
  const duplicates = await elRawSearch(query);
  const { buckets } = duplicates.aggregations.url.duplicateUri;
  logApp.info(`[MIGRATION] Merging ${buckets.length} URL`);
  // end region
  // For each duplicate, merge all entities into one.
  for (let index = 0; index < buckets.length; index += 1) {
    const bucket = buckets[index];
    const { key: url } = bucket;
    // Find all elements with this key
    const findQuery = {
      index: READ_INDEX_STIX_CYBER_OBSERVABLES,
      ignore_throttled: ES_IGNORE_THROTTLED,
      body: {
        query: {
          bool: {
            must: [
              { term: { 'entity_type.keyword': { value: 'Url' } } },
              { term: { 'value.keyword': { value: url } } },
            ],
          },
        },
        sort: [{ 'internal_id.keyword': 'desc' }],
      },
    };
    const data = await elRawSearch(findQuery);
    const urlsToMerge = data.hits.hits;
    const target = R.head(urlsToMerge)._source;
    // 1. Update the standard_id of the target
    const { element: updatedTarget } = await patchAttribute(SYSTEM_USER, target.internal_id, target.entity_type, {
      standard_id: generateStandardId(target.entity_type, target),
    });
    const elementsToMerge = urlsToMerge.slice(1);
    const sources = elementsToMerge.map((s) => s._source.internal_id);
    // 2. Merge everything else inside the target
    await mergeEntities(SYSTEM_USER, updatedTarget.internal_id, sources);
    logApp.info(
      `[MIGRATION] URL ${updatedTarget.value} merged (${urlsToMerge.length}) -- ${index + 1}/${buckets.length}`
    );
  }
  next();
};

export const down = async (next) => {
  // Nop.
  next();
};
