import { describe, expect, it, beforeAll, afterAll } from 'vitest';
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
  const lastModified = '2023-01-01T00:00:00.000Z';

  const globalPath = 'import/global';
  const fileName = 'fileToTestRetentionRule';
  const fileId = `${globalPath}/${fileName}`;
  const progressFileName = 'progressFile';
  const progressFileId = `${globalPath}/${progressFileName}`;

  const pendingPath = 'import/pending';
  const workbench1Name = 'workbench1';
  const workbench1Id = `${pendingPath}/${workbench1Name}`;
  const workbench2Name = 'workbench2';
  const workbench2Id = `${pendingPath}/${workbench2Name}`;

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
  beforeAll(async () => {
    // create a file not modified since '2023-01-01T00:00:00.000Z'
    const fileToUpload = {
      createReadStream: () => Readable.from('This is a file content.'),
      filename: fileName,
    };
    await uploadToStorage(context, ADMIN_USER, globalPath, fileToUpload, {});
    const fileUpdateQuery = {
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
      body: fileUpdateQuery
    }).catch((err: Error) => {
      throw DatabaseError('Error updating elastic', { cause: err });
    });
    const file = await loadFile(context, ADMIN_USER, fileId);
    expect(file?.lastModified).toEqual(lastModified);
    expect(file?.uploadStatus).toEqual('complete');
    expect(file?.id).toEqual(fileId);
    // create a file not modified since '2023-01-01T00:00:00.000Z' and with uploadStatus = 'pending'
    const progressFileToUpload = {
      createReadStream: () => Readable.from('This is a file content.'),
      filename: progressFileName,
    };
    await uploadToStorage(context, ADMIN_USER, globalPath, progressFileToUpload, {});
    const progressFileUpdateQuery = {
      script: {
        params: { lastModified, progress: 'progress' },
        source: 'ctx._source.lastModified = params.lastModified; ctx._source.uploadStatus = params.progress;',
      },
      query: {
        bool: {
          must: [
            { term: { 'internal_id.keyword': { value: progressFileId } } },
          ],
        },
      },
    };
    await elRawUpdateByQuery({
      index: [READ_INDEX_INTERNAL_OBJECTS],
      refresh: true,
      wait_for_completion: true,
      body: progressFileUpdateQuery
    }).catch((err: Error) => {
      throw DatabaseError('Error updating elastic', { cause: err });
    });
    // create a workbench not modified since '2023-01-01T00:00:00.000Z'
    const workbench1ToUpload = {
      createReadStream: () => Readable.from('This is a file content.'),
      filename: workbench1Name,
    };
    await uploadToStorage(context, ADMIN_USER, pendingPath, workbench1ToUpload, {});
    const workbench1UpdateQuery = {
      script: {
        params: { lastModified },
        source: 'ctx._source.lastModified = params.lastModified;',
      },
      query: {
        bool: {
          must: [
            { term: { 'internal_id.keyword': { value: workbench1Id } } },
          ],
        },
      },
    };
    await elRawUpdateByQuery({
      index: [READ_INDEX_INTERNAL_OBJECTS],
      refresh: true,
      wait_for_completion: true,
      body: workbench1UpdateQuery
    }).catch((err: Error) => {
      throw DatabaseError('Error updating elastic', { cause: err });
    });
    const workbench1 = await loadFile(context, ADMIN_USER, workbench1Id);
    expect(workbench1?.lastModified).toEqual(lastModified);
    // create a workbench (not modified since now)
    const workbench2ToUpload = {
      createReadStream: () => Readable.from('This is a file content.'),
      filename: workbench2Name,
    };
    await uploadToStorage(context, ADMIN_USER, pendingPath, workbench2ToUpload, {});
  });
  afterAll(async () => {
    // delete the created files
    const deleted = await deleteFile(context, ADMIN_USER, fileId);
    expect(deleted?.id).toEqual(fileId);
    // const progressDeleted = await deleteFile(context, ADMIN_USER, progressFileId);
    // expect(progressDeleted?.id).toEqual(progressFileId);
    // delete the created workbenches
    const workbench1Deleted = await deleteFile(context, ADMIN_USER, workbench1Id);
    expect(workbench1Deleted?.id).toEqual(workbench1Id);
    const workbench2Deleted = await deleteFile(context, ADMIN_USER, workbench2Id);
    expect(workbench2Deleted?.id).toEqual(workbench2Id);
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
    // check the number of files imported in Data/import
    const files = await allFilesForPaths(testContext, ADMIN_USER, [globalPath]);
    expect(files.length).toEqual(9); // 7 files from index-file-test + the 2 created files
    // retention rule on files not modified since 2023-07-01
    const before = utcDate('2023-07-01T00:00:00.000Z');
    const filesToDelete = await elementsToDelete(context, 'file', before);
    expect(filesToDelete.edges.length).toEqual(1); // fileToTestRetentionRule is the only file that has not been modified since 'before' and with uploadStatus = complete
    expect(filesToDelete.edges[0].node.id).toEqual(fileId);
    // retention rule on all the files
    const filesToDelete2 = await elementsToDelete(context, 'file', utcDate());
    expect(filesToDelete2.edges.length).toEqual(8); // all the files that has not been modified since now and with uploadStatus = complete
  });
  it('should fetch the correct files to be deleted by a retention rule on workbenches', async () => {
    // retention rule on workbenches not modified since 2023-07-01
    const before = utcDate('2023-07-01T00:00:00.000Z');
    const filesToDelete = await elementsToDelete(context, 'workbench', before);
    expect(filesToDelete.edges.length).toEqual(1); // workbench1 is the only workbench that has not been modified since 'before'
    expect(filesToDelete.edges[0].node.id).toEqual(workbench1Id);
  });
});
