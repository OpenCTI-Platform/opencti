import { logMigration } from '../config/conf';
import { elRawDeleteByQuery, elRawSearch, elUpdate } from '../database/engine';
import { READ_DATA_INDICES, READ_INDEX_STIX_META_RELATIONSHIPS } from '../database/utils';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { DatabaseError } from '../config/errors';

const message = '[MIGRATION] remove multiple authors from entities that have multiple rel_created-by.internal_id';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
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
  logMigration.info(`[MIGRATION] Found ${multipleAuthorsHits?.length} entities with multiple authors`);
  // For each entity with multiple authors, keep only one author, and also delete corresponding ref relations
  for (let index = 0; index < multipleAuthorsHits?.length; index += 1) {
    const currentEntityWithMultipleAuthors = multipleAuthorsHits[index];
    const currentAuthorsIds = currentEntityWithMultipleAuthors._source['rel_created-by.internal_id'];
    const authorIdToKeep = currentAuthorsIds[currentAuthorsIds.length - 1];
    // 1. Update the denormalized refs of the current entity
    const updateCreatedByWithUniqueIdSource = "ctx._source['rel_created-by.internal_id'] = [params.authorIdToKeep]";
    await elUpdate(currentEntityWithMultipleAuthors._index, currentEntityWithMultipleAuthors._id, {
      script: { source: updateCreatedByWithUniqueIdSource, lang: 'painless', params: { authorIdToKeep } },
    });

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

    await elRawDeleteByQuery({
      index: READ_INDEX_STIX_META_RELATIONSHIPS,
      refresh: true,
      wait_for_completion: true,
      body: allCreateByRefsExceptAuthorToKeepQuery,
    }).catch((err) => {
      throw DatabaseError('Error cleaning the created by refs', { cause: err });
    });

    if ((index + 1) % 10 === 0) {
      logMigration.info(`[MIGRATION] Entity ${currentEntityWithMultipleAuthors._id} authors cleaned -- ${index + 1}/${multipleAuthorsHits.length}`);
    }
  }

  logMigration.info(`${message} > done`);
  next();
};
