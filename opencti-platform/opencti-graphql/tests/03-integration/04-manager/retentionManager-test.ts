import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import gql from 'graphql-tag';
import { Readable } from 'stream';
import { ADMIN_USER, queryAsAdmin, TEST_ORGANIZATION, testContext } from '../../utils/testQuery';
import { utcDate } from '../../../src/utils/format';
import { deleteElement, getElementsToDelete } from '../../../src/manager/retentionManager';
import { allFilesForPaths } from '../../../src/modules/internal/document/document-domain';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { uploadToStorage } from '../../../src/database/file-storage';
import { elLoadById, elRawUpdateByQuery } from '../../../src/database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../../src/database/utils';
import { DatabaseError } from '../../../src/config/errors';
import { deleteFile, loadFile } from '../../../src/database/file-storage';
import { deleteElementById } from '../../../src/database/middleware';
import { canDeleteElement } from '../../../src/database/data-consistency';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../../src/schema/stixDomainObject';

describe('Retention Manager tests ', () => {
  const context = testContext;
  const lastModified = '2023-01-01T00:00:00.000Z';

  const globalPath = 'import/global';
  const fileName = 'fileToTestRetentionRule';
  const fileId = `${globalPath}/${fileName.toLowerCase()}`;
  const progressFileName = 'progressFile';
  const progressFileId = `${globalPath}/${progressFileName}`;

  const pendingPath = 'import/pending';
  const workbench1Name = 'workbench1';
  const workbench1Id = `${pendingPath}/${workbench1Name}`;
  const workbench2Name = 'workbench2';
  const workbench2Id = `${pendingPath}/${workbench2Name}`;
  let report1Id = '';
  let report2Id = '';

  let filesToDelete;
  let workbenchesToDelete;

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

  const CREATE_REPORT_QUERY = gql`
    mutation ReportAdd($input: ReportAddInput!) {
      reportAdd(input: $input) {
        id
        standard_id
        name
        description
        published
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
    // create a file not modified since '2023-01-01T00:00:00.000Z' and with uploadStatus = 'progress'
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
    // create a report not modified since '2023-01-01T00:00:00.000Z'
    const REPORT1_TO_CREATE = {
      input: {
        name: 'report1',
        description: 'Report description',
        published: '2020-02-26T00:51:35.000Z',
        objects: [
          'campaign--92d46985-17a6-4610-8be8-cc70c82ed214',
          'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02',
        ],
      },
    };
    const report1 = await queryAsAdmin({
      query: CREATE_REPORT_QUERY,
      variables: REPORT1_TO_CREATE,
    });
    report1Id = <string>report1?.data?.reportAdd?.id || '';
    const report1UpdateQuery = {
      script: {
        params: { lastModified },
        source: 'ctx._source.updated_at = params.lastModified;',
      },
      query: {
        bool: {
          must: [
            { term: { 'internal_id.keyword': { value: report1Id } } },
          ],
        },
      },
    };
    await elRawUpdateByQuery({
      index: [READ_INDEX_STIX_DOMAIN_OBJECTS],
      refresh: true,
      wait_for_completion: true,
      body: report1UpdateQuery
    }).catch((err: Error) => {
      throw DatabaseError('Error updating elastic', { cause: err });
    });
    // create a report (not modified since now)
    const REPORT2_TO_CREATE = {
      input: {
        name: 'report2',
        description: 'Report description',
        published: '2020-02-26T00:51:35.000Z',
        objects: [
          'campaign--92d46985-17a6-4610-8be8-cc70c82ed214',
          'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02',
        ],
      },
    };
    const report2 = await queryAsAdmin({
      query: CREATE_REPORT_QUERY,
      variables: REPORT2_TO_CREATE,
    });
    report2Id = <string>report2?.data?.reportAdd?.id || '';
  });
  afterAll(async () => {
    // delete the remaining file
    const progressDeleted = await deleteFile(context, ADMIN_USER, progressFileId);
    expect(progressDeleted?.id).toEqual(progressFileId);
    // delete the remaining workbench
    const workbench2Deleted = await deleteFile(context, ADMIN_USER, workbench2Id);
    expect(workbench2Deleted?.id).toEqual(workbench2Id);
    // delete the remaining report
    const report2Deleted = await deleteElementById(context, ADMIN_USER, report2Id, ENTITY_TYPE_CONTAINER_REPORT);
    expect(report2Deleted?.id).toEqual(report2Id);
  });
  it('should create and delete retention rules', async () => {
    // create retention rules
    const knowledgeRule_toCreate = {
      input: {
        name: 'Knowledge rule',
        max_retention: 2,
        retention_unit: 'days',
        scope: 'knowledge',
        filters: emptyStringFilters,
      }
    };
    const fileRule_toCreate = {
      input: {
        name: 'File rule',
        max_retention: 2,
        retention_unit: 'days',
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
    filesToDelete = await getElementsToDelete(context, 'file', before);
    expect(filesToDelete.edges.length).toEqual(1); // fileToTestRetentionRule is the only file that has not been modified since 'before' and with uploadStatus = complete
    expect(filesToDelete.edges[0].node.id).toEqual(fileId);
    // retention rule on all the files
    const filesToDelete2 = await getElementsToDelete(context, 'file', utcDate());
    expect(filesToDelete2.edges.length).toEqual(8); // all the files that has not been modified since now and with uploadStatus = complete
  });
  it('should fetch the correct files to be deleted by a retention rule on workbenches', async () => {
    // retention rule on workbenches not modified since 2023-07-01
    const before = utcDate('2023-07-01T00:00:00.000Z');
    workbenchesToDelete = await getElementsToDelete(context, 'workbench', before);
    expect(workbenchesToDelete.edges.length).toEqual(1); // workbench1 is the only workbench that has not been modified since 'before'
    expect(workbenchesToDelete.edges[0].node.id).toEqual(workbench1Id);
  });
  it('should fetch the correct report to be deleted by a retention rule on knowledge', async () => {
    // retention rule on knowledge not modified since 2023-07-01
    const before = utcDate('2023-07-01T00:00:00.000Z');
    const reportsToDelete = await getElementsToDelete(context, 'knowledge', before);
    expect(reportsToDelete.edges.length).toEqual(1);
    expect(reportsToDelete.edges[0].node.id).toEqual(report1Id);
    const canDeleteReport = await canDeleteElement(context, ADMIN_USER, reportsToDelete.edges[0].node);
    expect(canDeleteReport).toBeTruthy();
  });
  it('should fetch individuals to delete', async () => {
    // retention rule on workbenches not modified since 2023-07-01
    const before = utcDate();
    const filters = {
      mode: 'and',
      filters: [{
        key: ['entity_type'],
        values: [ENTITY_TYPE_IDENTITY_INDIVIDUAL],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const elementsToDelete = await getElementsToDelete(context, 'knowledge', before, JSON.stringify(filters));
    expect(elementsToDelete.edges.length).toEqual(3);
    const adminIndividual = elementsToDelete.edges.find((e: any) => e.node.name === 'admin');
    expect(await canDeleteElement(context, ADMIN_USER, adminIndividual.node)).toBeFalsy();
    const otherIndividual = elementsToDelete.edges.find((e: any) => !e.node.contact_information);
    expect(await canDeleteElement(context, ADMIN_USER, otherIndividual.node)).toBeTruthy();
  });
  it('should delete the fetched files and workbenches', async () => {
    // delete file
    await deleteElement(context, 'file', fileId); // should delete fileToTestRetentionRule
    const files = await allFilesForPaths(testContext, ADMIN_USER, [globalPath]);
    expect(files.length).toEqual(8); // 7 files from index-file-test + the 2 created files - fileToTestRetentionRule that should have been deleted
    // delete workbench
    await deleteElement(context, 'workbench', workbench1Id); // should delete workbench1
    const workbenches = await allFilesForPaths(testContext, ADMIN_USER, [pendingPath]);
    expect(workbenches.length).toEqual(1); // the 2 created workbenches - workbench1 that should have been deleted
    // delete report
    await deleteElement(context, 'knowledge', report1Id, { knowledgeType: ENTITY_TYPE_CONTAINER_REPORT, forceRefresh: true }); // should delete report1
    const report1deleted = await elLoadById(testContext, ADMIN_USER, report1Id);
    expect(report1deleted).toBeUndefined();
  });
  it('should not delete organization with members', async () => {
    await expect(() => deleteElement(context, 'knowledge', TEST_ORGANIZATION.id, { knowledgeType: ENTITY_TYPE_IDENTITY_ORGANIZATION }))
      .rejects.toThrowError('Cannot delete an organization that has members.');
  });
  it('should not delete individual associated to user', async () => {
    const individualUserId = 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91'; // admin individual
    await expect(() => deleteElement(context, 'knowledge', individualUserId, { knowledgeType: ENTITY_TYPE_IDENTITY_INDIVIDUAL }))
      .rejects.toThrowError('Cannot delete an individual corresponding to a user');
  });
});
