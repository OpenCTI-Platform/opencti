/* eslint-disable no-underscore-dangle,no-await-in-loop */
import * as R from 'ramda';
import { el } from '../database/elasticSearch';
import { INDEX_STIX_CYBER_OBSERVABLES } from '../database/utils';
import { loadByIdFullyResolved, mergeEntities, patchAttribute } from '../database/middleware';
import { SYSTEM_USER } from '../domain/user';
import { generateStandardId } from '../schema/identifier';
import { logger } from '../config/conf';

export const up = async (next) => {
  // region find duplicates
  const query = {
    index: INDEX_STIX_CYBER_OBSERVABLES,
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
  const duplicates = await el.search(query);
  const { buckets } = duplicates.body.aggregations.url.duplicateUri;
  logger.info(`[MIGRATION] Merging ${buckets.length} URL`);
  // end region
  // For each duplicate, merge all entities into one.
  for (let index = 0; index < buckets.length; index += 1) {
    const bucket = buckets[index];
    const { key: url } = bucket;
    // Find all elements with this key
    const findQuery = {
      index: INDEX_STIX_CYBER_OBSERVABLES,
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
    const data = await el.search(findQuery);
    const urlsToMerge = data.body.hits.hits;
    const target = R.head(urlsToMerge)._source;
    // 1. Update the standard_id of the target
    const updatedTarget = await patchAttribute(SYSTEM_USER, target.internal_id, target.entity_type, {
      standard_id: generateStandardId(target.entity_type, target),
    });
    const elementsToMerge = urlsToMerge.slice(1);
    const resolveElementsToMerge = await Promise.all(
      elementsToMerge.map((e) => loadByIdFullyResolved(e._source.internal_id))
    );
    const sources = resolveElementsToMerge.map((s) => R.assoc('standard_id', updatedTarget.standard_id, s));
    // 2. Merge everything else inside the target
    await mergeEntities(SYSTEM_USER, updatedTarget, sources);
    logger.info(
      `[MIGRATION] URL ${updatedTarget.value} merged (${urlsToMerge.length}) -- ${index + 1}/${buckets.length}`
    );
  }
  next();
};

export const down = async (next) => {
  // Nop.
  next();
};
