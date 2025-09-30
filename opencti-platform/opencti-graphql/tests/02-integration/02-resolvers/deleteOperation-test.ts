import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_API_TOKEN, ADMIN_USER, API_URI, editorQuery, PYTHON_PATH, queryAsAdmin, TEST_ORGANIZATION, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { MARKING_TLP_AMBER_STRICT, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { wait } from '../../../src/database/utils';
import { execChildPython } from '../../../src/python/pythonBridge';

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

const DELETE_REPORT_QUERY = gql`
    mutation reportDelete($id: ID!) {
        reportEdit(id: $id) {
            delete
        }
    }
`;

const READ_REPORT_QUERY = gql`
    query report($id: String!) {
        report(id: $id) {
            id
            standard_id
            name
            description
            published
            toStix
            importFiles {
                edges {
                    node { 
                        id
                        name
                    }
                }
            }
        }
    }
`;

const READ_DELETE_OPERATION_QUERY = gql`
    query deleteOperation($id: String!) {
        deleteOperation(id: $id) {
            id
            created_at
            deletedBy { 
                id
                name
            }
            confidence,
            objectMarking {
                standard_id
            }
            main_entity_name
            main_entity_type
            main_entity_id
            deleted_elements {
                id
                source_index
            }
        }
    }
`;

const LIST_DELETE_OPERATION_QUERY = gql`
    query deleteOperations(
        $first: Int
        $after: ID
        $orderBy: DeleteOperationOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
        $search: String
    ) {
        deleteOperations(
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
                    created_at
                    deletedBy {
                        id
                        name
                    }
                    confidence,
                    objectMarking {
                        standard_id
                    }
                    main_entity_name
                    main_entity_type
                    main_entity_id
                    deleted_elements {
                        id
                        source_index
                    }
                }
            }
        }
    }
`;

const DELETE_CONFIRM_MUTATION = gql`
    mutation deleteOperationConfirm($id: ID!) {
        deleteOperationConfirm(id: $id)
    }
`;

const DELETE_RESTORE_MUTATION = gql`
    mutation deleteOperationRestore($id: ID!) {
        deleteOperationRestore(id: $id)
    }
`;

const CREATE_INDICATOR_QUERY = gql`
  mutation IndicatorAdd($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) {
      id
      name
    }
  }
`;

const DELETE_INDICATOR_QUERY = gql`
  mutation IndicatorDeletionDeleteMutation($id: ID!) {
      indicatorDelete(id: $id)
  }
`;

const filename = './tests/data/poisonivy.json';

describe('Delete operation resolver testing', () => {
  let reportInternalId = '';
  let deleteOperationId = '';

  it('should deleteOperation be created', async () => {
  // Create and delete the report
    const REPORT_TO_CREATE = {
      input: {
        name: 'Report for deletion',
        description: 'Report for deletion description',
        published: '2020-02-26T00:51:35.000Z',
        confidence: 90,
        objectMarking: [MARKING_TLP_RED],
        objectOrganization: [TEST_ORGANIZATION.id],
      },
    };
    const report = await queryAsAdmin({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_CREATE });
    reportInternalId = report.data?.reportAdd.id;
    expect(reportInternalId).toBeDefined();

    // upload a file to this report, to also test it after permanent deletion
    const uploadOpts = [API_URI, ADMIN_API_TOKEN, reportInternalId, filename, [MARKING_TLP_AMBER_STRICT]];
    const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_uploader.py', uploadOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
    const reportAfterImport = await queryAsAdminWithSuccess({ query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
    expect(reportAfterImport.data?.report.id).toBe(reportInternalId);
    expect(reportAfterImport.data?.report.importFiles.edges[0].node.name).toBe('poisonivy.json');

    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: reportInternalId }, });

    // Check that an associated delete operation was created
    const getAllDeletedOperations = await queryAsAdminWithSuccess({ query: LIST_DELETE_OPERATION_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filters: [{
            key: 'main_entity_id',
            values: reportInternalId,
            operator: 'eq',
            mode: 'or',
          }],
          filterGroups: [],
        } } });
    expect(getAllDeletedOperations.data?.deleteOperations.edges.length).toEqual(1);
    deleteOperationId = getAllDeletedOperations.data?.deleteOperations.edges[0].node.id;

    const getDeleteOperation = await queryAsAdmin({ query: READ_DELETE_OPERATION_QUERY, variables: { id: deleteOperationId, }, });
    expect(getDeleteOperation.data?.deleteOperation).toBeDefined();
    expect(getDeleteOperation.data?.deleteOperation.main_entity_type).toBe(ENTITY_TYPE_CONTAINER_REPORT);
    expect(getDeleteOperation.data?.deleteOperation.main_entity_id).toBe(reportInternalId);
    expect(getDeleteOperation.data?.deleteOperation.deleted_elements.length).toBe(3); // main entity + ref to marking + ref to organization
    expect(getDeleteOperation.data?.deleteOperation.deleted_elements[0].id).toBe(reportInternalId);
    expect(getDeleteOperation.data?.deleteOperation.confidence).toBe(90);
    expect(getDeleteOperation.data?.deleteOperation.objectMarking.length).toBe(1);
    expect(getDeleteOperation.data?.deleteOperation.objectMarking[0].standard_id).toBe(MARKING_TLP_RED);
  });

  it('should Participant user not be allowed to list deleteOperations', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, { query: LIST_DELETE_OPERATION_QUERY, variables: { first: 10 } });
  });

  it('should TLP:AMBER user not be able to query TLP_RED deleteOperation', async () => {
    const getDeleteOperation = await editorQuery({ query: READ_DELETE_OPERATION_QUERY, variables: { id: deleteOperationId, }, });
    expect(getDeleteOperation.data?.deleteOperation).toBeNull();
  });

  it('should deleteOperation be confirmed', async () => {
    await queryAsAdmin({ query: DELETE_CONFIRM_MUTATION, variables: { id: deleteOperationId }, });

    const queryResult = await queryAsAdminWithSuccess({ query: READ_DELETE_OPERATION_QUERY, variables: { id: deleteOperationId } });
    expect(queryResult.data?.deleteOperation).toBeNull();
  });

  it('should deleteOperation be restored', async () => {
    // Create and delete the report
    const REPORT_TO_CREATE = {
      input: {
        name: 'Report for restore',
        description: 'Report for restore description',
        published: '2020-02-26T00:51:35.000Z',
      },
    };

    const report = await queryAsAdmin({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_CREATE });
    reportInternalId = report.data?.reportAdd.id;
    // import a file to this report, to also test it after restore
    const uploadOpts = [API_URI, ADMIN_API_TOKEN, reportInternalId, filename, [MARKING_TLP_AMBER_STRICT]];
    const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_uploader.py', uploadOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');

    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: reportInternalId }, });

    // Retrieve the associated delete operation
    const getAllDeletedOperations = await queryAsAdminWithSuccess({ query: LIST_DELETE_OPERATION_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filters: [{
            key: 'main_entity_id',
            values: [reportInternalId],
            operator: 'eq',
            mode: 'or',
          }],
          filterGroups: [],
        } } });
    expect(getAllDeletedOperations.data?.deleteOperations.edges.length).toEqual(1);
    deleteOperationId = getAllDeletedOperations.data?.deleteOperations.edges[0].node.id;

    // Restore the report (wait 5s for report deletion lock to expire before restoring)
    await wait(5010);
    await queryAsAdmin({ query: DELETE_RESTORE_MUTATION, variables: { id: deleteOperationId }, });

    const deleteOperationQueryResult = await queryAsAdminWithSuccess({ query: READ_DELETE_OPERATION_QUERY, variables: { id: deleteOperationId } });
    expect(deleteOperationQueryResult.data?.deleteOperation).toBeNull();

    const reportQueryAfterResult = await queryAsAdminWithSuccess({ query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
    expect(reportQueryAfterResult.data?.report.id).toBe(reportInternalId);
    expect(reportQueryAfterResult.data?.report.importFiles.edges[0].node.name).toBe('poisonivy.json');

    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: reportInternalId }, });
  });

  it('should find all entities and relationships when restoring deleteOperation', async () => {
    const INDICATOR_TO_CREATE = {
      input: {
        name: 'xxxx',
        description: '',
        indicator_types: [],
        pattern: 'patternshodan',
        pattern_type: 'shodan',
        createObservables: false,
        x_opencti_main_observable_type: 'Artifact',
        x_mitre_platforms: [],
        confidence: 100,
        x_opencti_score: null,
        x_opencti_detection: false,
        valid_from: null,
        valid_until: null,
        killChainPhases: [],
        objectMarking: [],
        objectLabel: [],
        externalReferences: []
      }
    };

    const indicator = await queryAsAdmin({ query: CREATE_INDICATOR_QUERY, variables: INDICATOR_TO_CREATE });
    const indicatorId = indicator.data?.indicatorAdd.id;
    expect(indicatorId).toBeDefined();

    const REPORT_TO_CREATE = {
      input: {
        name: 'Report with entities',
        description: 'Report to test entity restoration',
        published: '2025-09-29T08:43:07.000Z',
        confidence: 100,
        objectMarking: [MARKING_TLP_AMBER_STRICT],
        objects: [indicatorId],
      },
    };

    const report = await queryAsAdmin({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_CREATE });
    reportInternalId = report.data?.reportAdd.id;
    expect(reportInternalId).toBeDefined();

    // Verify the report has the objects relationships
    const READ_REPORT_WITH_OBJECTS_QUERY = gql`
      query report($id: String!) {
        report(id: $id) {
          id
          standard_id
          name
          objects {
            edges {
              node {
                ... on BasicObject {
                  id
                  entity_type
                }
              }
            }
          }
        }
      }
    `;

    const reportBeforeDelete = await queryAsAdminWithSuccess({
      query: READ_REPORT_WITH_OBJECTS_QUERY,
      variables: { id: reportInternalId }
    });
    expect(reportBeforeDelete.data?.report.objects.edges.length).toBe(1);
    const objectIds = reportBeforeDelete.data?.report.objects.edges.map((e: any) => e.node.id);
    expect(objectIds).toContain(indicatorId);

    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: reportInternalId } });

    // Get the delete operation
    const getAllDeletedOperations = await queryAsAdminWithSuccess({
      query: LIST_DELETE_OPERATION_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filters: [{
            key: 'main_entity_id',
            values: [reportInternalId],
            operator: 'eq',
            mode: 'or',
          }],
          filterGroups: [],
        }
      }
    });
    expect(getAllDeletedOperations.data?.deleteOperations.edges.length).toEqual(1);
    deleteOperationId = getAllDeletedOperations.data?.deleteOperations.edges[0].node.id;

    const deleteOperation = await queryAsAdminWithSuccess({
      query: READ_DELETE_OPERATION_QUERY,
      variables: { id: deleteOperationId }
    });

    // Verify that deleted_elements includes:
    // - the main entity (report)
    // - the 'objects' relationships (1 relationships to indicator)
    // - marking ref relationship (1)
    // Should be at least 3 elements total
    expect(deleteOperation.data?.deleteOperation.deleted_elements.length).toBeGreaterThanOrEqual(3);
    const deletedElementsIds = deleteOperation.data?.deleteOperation.deleted_elements.map((el: any) => el.id);
    expect(deletedElementsIds).toContain(reportInternalId);

    // Wait for deletion lock to expire
    await wait(5010);

    const restoreResult = await queryAsAdmin({
      query: DELETE_RESTORE_MUTATION,
      variables: { id: deleteOperationId }
    });
    expect(restoreResult.errors).toBeUndefined();

    // Verify the report and its relationships are restored
    const reportAfterRestore = await queryAsAdminWithSuccess({
      query: READ_REPORT_WITH_OBJECTS_QUERY,
      variables: { id: reportInternalId }
    });
    expect(reportAfterRestore.data?.report.id).toBe(reportInternalId);
    expect(reportAfterRestore.data?.report.objects.edges.length).toBe(1);
    const restoredObjectIds = reportAfterRestore.data?.report.objects.edges.map((e: any) => e.node.id);
    expect(restoredObjectIds).toContain(indicatorId);

    // Cleanup
    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: reportInternalId } });
    const cleanupDeleteOps = await queryAsAdminWithSuccess({
      query: LIST_DELETE_OPERATION_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filters: [{
            key: 'main_entity_id',
            values: [reportInternalId],
            operator: 'eq',
            mode: 'or',
          }],
          filterGroups: [],
        }
      }
    });

    if (cleanupDeleteOps.data && cleanupDeleteOps.data?.deleteOperations.edges.length > 0) {
      await queryAsAdmin({
        query: DELETE_CONFIRM_MUTATION,
        variables: { id: cleanupDeleteOps.data.deleteOperations.edges[0].node.id }
      });

      await queryAsAdmin({
        query: DELETE_INDICATOR_QUERY,
        variables: { id: indicatorId }
      });
    }
  });
});
