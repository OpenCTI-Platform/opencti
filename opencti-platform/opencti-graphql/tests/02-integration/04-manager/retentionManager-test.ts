import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { utcDate } from '../../../src/utils/format';
import { elementsToDelete } from '../../../src/manager/retentionManager';
import { allFilesForPaths } from '../../../src/modules/internal/document/document-domain';

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
    // check the number of files imported in Data/import
    const globalPath = 'import/global';
    const files = await allFilesForPaths(testContext, ADMIN_USER, [globalPath]);
    expect(files.length).toEqual(7); // 7 files from index-file-test
    // retention rule on files not modified since 2023-01-01
    const before = utcDate('2023-01-01T00:00:00.000Z');
    const filesToDelete = await elementsToDelete(context, 'file', before);
    expect(filesToDelete.edges.length).toEqual(1); // 'TEST_FILE_7' has not been modified since 'before'
    expect(filesToDelete.edges[0].node.id).toEqual('test');
    // retention rule on all the files
    const filesToDelete2 = await elementsToDelete(context, 'file', utcDate());
    expect(filesToDelete2.edges.length).toEqual(7); // all the files has not been modified since now
  });
  it('should fetch the correct elements to be deleted by a retention rule on knowledge', async () => {
    const before = utcDate('2021-01-01T00:00:00.000Z');
    const elements = await elementsToDelete(context, 'knowledge', before);
    expect(elements.pageInfo.globalCount).toEqual(0);
  });
});
