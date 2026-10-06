import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_API_TOKEN, ADMIN_USER, API_URI, PYTHON_PATH, TEST_ORGANIZATION, testContext, USER_EDITOR, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { queryAsAdminWithSuccess, queryAsUser, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { MARKING_TLP_AMBER_STRICT, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { INDEX_DELETED_OBJECTS, wait } from '../../../src/database/utils';
import { elDeleteElements, elReindexElements, elUpdate } from '../../../src/database/engine';
import { internalLoadById, storeLoadById } from '../../../src/database/middleware-loader';
import { deleteAllObjectFiles } from '../../../src/database/file-storage';
import { buildRefRelationKey } from '../../../src/schema/general';
import { RELATION_OBJECT_MARKING } from '../../../src/schema/stixRefRelationship';
import { execChildPython } from '../../../src/python/pythonBridge';
import type { BasicStoreBase, BasicStoreObject } from '../../../src/types/store';

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
            objects {
                edges {
                    node {
                        ... on BasicObject {
                            id
                            standard_id
                        }
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

    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: reportInternalId } });

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

    const getDeleteOperation = await queryAsAdmin({ query: READ_DELETE_OPERATION_QUERY, variables: { id: deleteOperationId } });
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
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: LIST_DELETE_OPERATION_QUERY, variables: { first: 10 } });
  });

  it('should TLP:AMBER user not be able to query TLP_RED deleteOperation', async () => {
    const getDeleteOperation = await queryAsUser(USER_EDITOR, { query: READ_DELETE_OPERATION_QUERY, variables: { id: deleteOperationId } });
    expect(getDeleteOperation.data?.deleteOperation).toBeNull();
  });

  it('should deleteOperation be confirmed', async () => {
    await queryAsAdmin({ query: DELETE_CONFIRM_MUTATION, variables: { id: deleteOperationId } });

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
        objects: ['campaign--bce98eb5-25a9-5ba7-b4a0-b160a79d0de7'],
      },
    };

    const report = await queryAsAdmin({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_CREATE });
    reportInternalId = report.data?.reportAdd.id;
    // import a file to this report, to also test it after restore
    const uploadOpts = [API_URI, ADMIN_API_TOKEN, reportInternalId, filename, [MARKING_TLP_AMBER_STRICT]];
    const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_uploader.py', uploadOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');

    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: reportInternalId } });

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
    await queryAsAdmin({ query: DELETE_RESTORE_MUTATION, variables: { id: deleteOperationId } });

    const deleteOperationQueryResult = await queryAsAdminWithSuccess({ query: READ_DELETE_OPERATION_QUERY, variables: { id: deleteOperationId } });
    expect(deleteOperationQueryResult.data?.deleteOperation).toBeNull();

    const reportQueryAfterResult = await queryAsAdminWithSuccess({ query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
    expect(reportQueryAfterResult.data?.report.id).toBe(reportInternalId);
    expect(reportQueryAfterResult.data?.report.importFiles.edges[0].node.name).toBe('poisonivy.json');

    // verify the objects relationship is restored
    expect(reportQueryAfterResult.data?.report.objects.edges.length).toEqual(1);
    expect(reportQueryAfterResult.data?.report.objects.edges[0].node.standard_id).toEqual('campaign--bce98eb5-25a9-5ba7-b4a0-b160a79d0de7');

    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: reportInternalId } });
  });

  it('should deleteOperation confirm only purge the trash when main entity is also live', async () => {
    // Create a report with a file, then delete it
    const REPORT_TO_CREATE = {
      input: {
        name: 'Report both live and in trash',
        description: 'Report both live and in trash description',
        published: '2020-02-26T00:51:35.000Z',
      },
    };
    const report = await queryAsAdmin({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_CREATE });
    const liveReportId = report.data?.reportAdd.id;
    expect(liveReportId).toBeDefined();
    const uploadOpts = [API_URI, ADMIN_API_TOKEN, liveReportId, filename, [MARKING_TLP_AMBER_STRICT]];
    const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_uploader.py', uploadOpts);
    expect(execution.status).toEqual('success');
    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: liveReportId } });

    const getAllDeletedOperations = await queryAsAdminWithSuccess({ query: LIST_DELETE_OPERATION_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filters: [{ key: 'main_entity_id', values: [liveReportId], operator: 'eq', mode: 'or' }],
          filterGroups: [],
        } } });
    expect(getAllDeletedOperations.data?.deleteOperations.edges.length).toEqual(1);
    const liveDeleteOperation = getAllDeletedOperations.data?.deleteOperations.edges[0].node;
    const mainDeletedElement = liveDeleteOperation.deleted_elements.find((el: { id: string }) => el.id === liveReportId);
    expect(mainDeletedElement.source_index).toBeDefined();

    // Simulate the inconsistent state: copy the trashed report back to its live index (trash copy is kept)
    await elReindexElements(testContext, ADMIN_USER, [liveReportId], INDEX_DELETED_OBJECTS, mainDeletedElement.source_index);
    const reportBackLive = await queryAsAdminWithSuccess({ query: READ_REPORT_QUERY, variables: { id: liveReportId } });
    expect(reportBackLive.data?.report.id).toBe(liveReportId);

    // Confirm must not fail on duplicate hits, and must only purge the trash
    await queryAsAdminWithSuccess({ query: DELETE_CONFIRM_MUTATION, variables: { id: liveDeleteOperation.id } });
    const deleteOperationResult = await queryAsAdminWithSuccess({ query: READ_DELETE_OPERATION_QUERY, variables: { id: liveDeleteOperation.id } });
    expect(deleteOperationResult.data?.deleteOperation).toBeNull();

    // Live report and its file are untouched
    const reportAfterConfirm = await queryAsAdminWithSuccess({ query: READ_REPORT_QUERY, variables: { id: liveReportId } });
    expect(reportAfterConfirm.data?.report.id).toBe(liveReportId);
    expect(reportAfterConfirm.data?.report.importFiles.edges[0].node.name).toBe('poisonivy.json');

    // Cleanup at engine level: no stream event, as the report came back live without one (keeps the sync tests consistent)
    const reportToClean = await storeLoadById(testContext, ADMIN_USER, liveReportId, ENTITY_TYPE_CONTAINER_REPORT) as BasicStoreObject;
    await deleteAllObjectFiles(testContext, ADMIN_USER, reportToClean);
    await elDeleteElements(testContext, ADMIN_USER, [reportToClean]);
    const reportAfterCleanup = await queryAsAdminWithSuccess({ query: READ_REPORT_QUERY, variables: { id: liveReportId } });
    expect(reportAfterCleanup.data?.report).toBeNull();
  });

  it('should deleteOperation confirm keep files when the live main entity is not visible to the user', async () => {
    // Report visible to USER_EDITOR (no marking, shared with its organization), with a file visible to USER_EDITOR
    const REPORT_TO_CREATE = {
      input: {
        name: 'Report live but restricted',
        description: 'Report live but restricted description',
        published: '2020-02-26T00:51:35.000Z',
        objectOrganization: [TEST_ORGANIZATION.id],
      },
    };
    const report = await queryAsAdminWithSuccess({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_CREATE });
    const restrictedReportId = report.data?.reportAdd.id;
    const uploadOpts = [API_URI, ADMIN_API_TOKEN, restrictedReportId, filename, [MARKING_TLP_GREEN]];
    const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_uploader.py', uploadOpts);
    expect(execution.status).toEqual('success');
    await queryAsAdminWithSuccess({ query: DELETE_REPORT_QUERY, variables: { id: restrictedReportId } });

    const getAllDeletedOperations = await queryAsAdminWithSuccess({ query: LIST_DELETE_OPERATION_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filters: [{ key: 'main_entity_id', values: [restrictedReportId], operator: 'eq', mode: 'or' }],
          filterGroups: [],
        } } });
    expect(getAllDeletedOperations.data?.deleteOperations.edges.length).toEqual(1);
    const restrictedDeleteOperation = getAllDeletedOperations.data?.deleteOperations.edges[0].node;
    const mainDeletedElement = restrictedDeleteOperation.deleted_elements.find((el: { id: string }) => el.id === restrictedReportId);

    // Report back live, then restricted to TLP:RED on the live copy only (trash copy stays visible to USER_EDITOR)
    await elReindexElements(testContext, ADMIN_USER, [restrictedReportId], INDEX_DELETED_OBJECTS, mainDeletedElement.source_index);
    const redMarking = await internalLoadById(testContext, ADMIN_USER, MARKING_TLP_RED) as BasicStoreBase;
    await elUpdate(testContext, mainDeletedElement.source_index, restrictedReportId, {
      script: { source: 'ctx._source[params.field] = params.ids', params: { field: buildRefRelationKey(RELATION_OBJECT_MARKING), ids: [redMarking.internal_id] } },
    });
    const reportAsEditor = await queryAsUser(USER_EDITOR, { query: READ_REPORT_QUERY, variables: { id: restrictedReportId } });
    expect(reportAsEditor.data?.report).toBeNull();
    const deleteOperationAsEditor = await queryAsUserWithSuccess(USER_EDITOR, { query: READ_DELETE_OPERATION_QUERY, variables: { id: restrictedDeleteOperation.id } });
    expect(deleteOperationAsEditor.data?.deleteOperation.id).toBe(restrictedDeleteOperation.id);

    // Confirm by a user who cannot see the live copy: must still detect it and keep its files
    await queryAsUserWithSuccess(USER_EDITOR, { query: DELETE_CONFIRM_MUTATION, variables: { id: restrictedDeleteOperation.id } });
    const deleteOperationResult = await queryAsAdminWithSuccess({ query: READ_DELETE_OPERATION_QUERY, variables: { id: restrictedDeleteOperation.id } });
    expect(deleteOperationResult.data?.deleteOperation).toBeNull();
    const reportAfterConfirm = await queryAsAdminWithSuccess({ query: READ_REPORT_QUERY, variables: { id: restrictedReportId } });
    expect(reportAfterConfirm.data?.report.id).toBe(restrictedReportId);
    expect(reportAfterConfirm.data?.report.importFiles.edges[0].node.name).toBe('poisonivy.json');

    // Cleanup at engine level: no stream event, as the report came back live without one (keeps the sync tests consistent)
    const reportToClean = await storeLoadById(testContext, ADMIN_USER, restrictedReportId, ENTITY_TYPE_CONTAINER_REPORT) as BasicStoreObject;
    await deleteAllObjectFiles(testContext, ADMIN_USER, reportToClean);
    await elDeleteElements(testContext, ADMIN_USER, [reportToClean]);
    const reportAfterCleanup = await queryAsAdminWithSuccess({ query: READ_REPORT_QUERY, variables: { id: restrictedReportId } });
    expect(reportAfterCleanup.data?.report).toBeNull();
  });
});
