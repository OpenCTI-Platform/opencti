import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { Readable } from 'stream';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { utcDate } from '../../../src/utils/format';
import { elementsToDelete } from '../../../src/manager/retentionManager';
import { allFilesForPaths } from '../../../src/modules/internal/document/document-domain';
import { uploadToStorage } from '../../../src/database/file-storage-helper';
import { elRawUpdateByQuery } from '../../../src/database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../../src/database/utils';
import { DatabaseError } from '../../../src/config/errors';
import { deleteFile, loadFile } from '../../../src/database/file-storage';

describe('Retention Manager tests ', () => {
  const context = testContext;
  const CREATE_RETENTION_QUERY = gql`
      mutation RetentionRuleAdd($input: RetentionRuleAddInput!) {
          retentionRuleAdd(input: $input) {
              id
              name
              scope
              filters
              max_retention
          }
      }
  `;
  const DELETE_RETENTION_QUERY = gql`
      mutation RetentionRuleDelete($id: ID!) {
          retentionRuleEdit(id: $id) {
              delete
          }
      }
  `;
  const emptyStringFilters = JSON.stringify({
    mode: 'and',
    filters: [],
    filterGroups: [],
  });
  it('should create and delete retention rules', async () => {
    // create retention rules
    const knowledgeRule_toCreate = {
      input: {
        name: 'Knowledge rule',
        max_retention: 2,
        scope: 'knowledge',
        filters: emptyStringFilters,
      }
    };
    const fileRule_toCreate = {
      input: {
        name: 'File rule',
        max_retention: 2,
        scope: 'file',
        filters: emptyStringFilters,
      }
    };
    const knowledgeRuleQuery = await queryAsAdmin({
      query: CREATE_RETENTION_QUERY,
      variables: knowledgeRule_toCreate,
    });
    const knowledgeRule = knowledgeRuleQuery.data?.retentionRuleAdd;
    expect(knowledgeRule.name).toEqual('Knowledge rule');
    expect(knowledgeRule.scope).toEqual('knowledge');
    expect(knowledgeRule.max_retention).toEqual(2);
    expect(knowledgeRule.id).not.toBeNull();
    const fileRuleQuery = await queryAsAdmin({
      query: CREATE_RETENTION_QUERY,
      variables: fileRule_toCreate,
    });
    const fileRule = fileRuleQuery.data?.retentionRuleAdd;
    expect(fileRule.name).toEqual('File rule');
    expect(fileRule.scope).toEqual('file');
    expect(fileRule.max_retention).toEqual(2);
    expect(fileRule.id).not.toBeNull();
    // delete retention rules
    const knowledgeRuleDeletion = await queryAsAdmin({
      query: DELETE_RETENTION_QUERY,
      variables: { id: knowledgeRule.id },
    });
    expect(knowledgeRuleDeletion.data?.retentionRuleEdit.delete).toEqual(knowledgeRule.id);
    const fileRuleDeletion = await queryAsAdmin({
      query: DELETE_RETENTION_QUERY,
      variables: { id: fileRule.id },
    });
    expect(fileRuleDeletion.data?.retentionRuleEdit.delete).toEqual(fileRule.id);
  });
  it('should fetch the correct files to be deleted by a retention rule on files', async () => {
    const globalPath = 'import/global';
    // create a file not modified since '2023-01-01T00:00:00.000Z'
    const fileName = 'fileToTestRetentionRule';
    const fileId = `${globalPath}/${fileName}`;
    const fileToUpload = {
      createReadStream: () => Readable.from('This is a file content.'),
      filename: fileName,
    };
    await uploadToStorage(context, ADMIN_USER, globalPath, fileToUpload, {});
    const lastModified = '2023-01-01T00:00:00.000Z';
    const updateQuery = {
      script: {
        params: { lastModified },
        source: 'ctx._source.lastModified = params.lastModified;',
      },
      query: {
        bool: {
          must: [
            { term: { 'internal_id.keyword': { value: fileId } } },
          ],
        },
      },
    };
    await elRawUpdateByQuery({
      index: [READ_INDEX_INTERNAL_OBJECTS],
      refresh: true,
      wait_for_completion: true,
      body: updateQuery
    }).catch((err: Error) => {
      throw DatabaseError('Error updating elastic', { cause: err });
    });
    const file = await loadFile(context, ADMIN_USER, fileId);
    expect(file?.lastModified).toEqual(lastModified);
    // check the number of files imported in Data/import
    const files = await allFilesForPaths(testContext, ADMIN_USER, [globalPath]);
    expect(files.length).toEqual(8); // 7 files from index-file-test + the created file
    // retention rule on files not modified since 2023-07-01
    const before = utcDate('2023-07-01T00:00:00.000Z');
    const filesToDelete = await elementsToDelete(context, 'file', before);
    expect(filesToDelete.edges.length).toEqual(1); // fileToTestRetentionRule is the only file that has not been modified since 'before'
    expect(filesToDelete.edges[0].node.id).toEqual(fileId);
    // retention rule on all the files
    const filesToDelete2 = await elementsToDelete(context, 'file', utcDate());
    expect(filesToDelete2.edges.length).toEqual(8); // all the files has not been modified since now
    // delete the created file
    const deleted = await deleteFile(context, ADMIN_USER, fileId);
    expect(deleted?.id).toEqual(fileId);
  });
  it('should fetch the correct elements to be deleted by a retention rule on knowledge', async () => {
    const before = utcDate('2024-01-01T00:00:00.000Z');
    const elements = await elementsToDelete(context, 'knowledge', before);
    expect(elements.pageInfo.globalCount).toEqual(0); // no entity have been modified since before
  });
});
