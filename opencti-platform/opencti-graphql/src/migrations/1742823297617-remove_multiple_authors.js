import { logApp } from '../config/conf';
import { elDeleteByQueryForMigration, elRawSearch, elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES, READ_INDEX_STIX_META_RELATIONSHIPS, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] remove multiple authors from entities that have multiple rel_created-by.internal_id';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  const query = {
    index: READ_DATA_INDICES,
    body: {
      query: {
        script: {
          script: {
            source: "doc['rel_created-by.internal_id.keyword'].length > 1",
            lang: 'painless'
          }
        }
      },
      size: 10000
    },
  };

  const multipleAuthorsData = await elRawSearch(context, SYSTEM_USER, '', query);
  const multipleAuthorsHits = multipleAuthorsData.hits?.hits;

  // For each entity with multiple authors, keep only one author, and also delete corresponding ref relations
  for (let index = 0; index < multipleAuthorsHits?.length; index += 1) {
    const currentEntityWithMultipleAuthors = multipleAuthorsHits[index];
    const currentAuthorsIds = currentEntityWithMultipleAuthors._source['rel_created-by.internal_id'];
    const authorIdToKeep = currentAuthorsIds[currentAuthorsIds.length - 1];
    // 1. Update the denormalized refs of the current entity
    const updateCreatedByWithUniqueIdSource = 'ctx._source.rel_created-by.internal_id = [params.authorIdToKeep];';
    const updateCreatedByWithUniqueIdQuery = {
      script: {
        source: updateCreatedByWithUniqueIdSource,
        params: { authorIdToKeep }
      },
      query: {
        match: {
          _id: currentEntityWithMultipleAuthors._id
        }
      }
    };
    await elUpdateByQueryForMigration('[MIGRATION] Updating entity to keep unique created by', [READ_RELATIONSHIPS_INDICES], updateCreatedByWithUniqueIdQuery);

    // 2. Delete all created-by ref relations that are not the unique author kept for entity

    const allCreateByRefsExceptAuthorToKeepQuery = {
      query: {
        bool: {
          must: [
            {
              term: { 'entity_type.keyword': { value: 'created-by' } }
            },
            {
              nested: {
                path: 'connections',
                query: {
                  bool: {
                    must: [
                      {
                        term: { 'connections.internal_id.keyword': { value: currentEntityWithMultipleAuthors._source.internal_id } }
                      }
                    ]
                  }
                }
              }
            }
          ],
          must_not: [
            {
              nested: {
                path: 'connections',
                query: {
                  bool: {
                    must: [
                      {
                        term: { 'connections.internal_id.keyword': { value: authorIdToKeep }
                        }
                      }
                    ]
                  }
                }
              }
            }
          ]
        }
      }
    };

    await elDeleteByQueryForMigration('[MIGRATION] Deleting multiple created-by', [READ_INDEX_STIX_META_RELATIONSHIPS], allCreateByRefsExceptAuthorToKeepQuery);

    logApp.info(`[MIGRATION] Entity ${currentEntityWithMultipleAuthors._id} authors cleaned -- ${index + 1}/${multipleAuthorsHits.length}`);
  }

  logApp.info(`${message} > done`);
  next();
};
