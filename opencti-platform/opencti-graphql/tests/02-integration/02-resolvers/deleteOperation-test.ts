import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { editorQuery, queryAsAdmin, TEST_ORGANIZATION, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';
import { wait } from '../../../src/database/utils';

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
    expect(getDeleteOperation.data?.deleteOperation.deleted_elements.length).toBe(7); // main entity + ref to marking + ref to organization
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

  it('should deleteOperation be deleted', async () => {
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

    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: reportInternalId }, });
  });
});
