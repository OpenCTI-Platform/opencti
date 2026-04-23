import { expect, it, describe, afterAll, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import { USER_CONNECTOR, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import type { ConnectorInfo, Connector } from '../../../src/generated/graphql';
import { BACKGROUND_TASK_QUEUES } from '../../../src/database/rabbitmq';
import { ENTITY_TYPE_BACKGROUND_TASK } from '../../../src/schema/internalObject';
import { IMPORT_CSV_CONNECTOR } from '../../../src/connector/importCsv/importCsv';
import { DRAFT_VALIDATION_CONNECTOR } from '../../../src/modules/draftWorkspace/draftWorkspace-connector';

const CREATE_WORK_QUERY = gql`
  mutation workAdd($connectorId: String!, $friendlyName: String, $isMultiPartWork: Boolean) {
    workAdd(connectorId: $connectorId, friendlyName: $friendlyName, isMultiPartWork: $isMultiPartWork) {
      id
    }
  }
`;

const LIST_WORK_QUERY = gql`
  query works(
    $first: Int
    $after: ID
    $orderBy: WorksOrdering
    $orderMode: OrderingMode
    $search: String
    $filters: FilterGroup
  ) {
    works(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      search: $search
      filters: $filters
    ) {
      edges {
        node {
          id
          name
          status
        }
      }
    }
  }
`;

const READ_WORK_QUERY = gql`
  query work($id: ID!) {
    work(id: $id) {
      id
      name
      status
      completed_number
    }
  }
`;

const UPDATE_WORK_QUERY = gql`
  mutation workToProcessed($id: ID!, $message: String, $inError: Boolean) {
    workEdit(id: $id) {
      toProcessed(message: $message, inError: $inError)
    }
  }
`;

const UPDATE_WORK_ADD_EXPECTATIONS_QUERY = gql`
  mutation workAddExpectations($id: ID!, $expectations: Int) {
    workEdit(id: $id) {
      addExpectations(expectations: $expectations)
    }
  }
`;

const UPDATE_WORK_REPORT_EXPECTATION_QUERY = gql`
  mutation workReportExpectation($id: ID!, $error: WorkErrorInput) {
    workEdit(id: $id) {
      reportExpectation(error: $error)
    }
  }
`;

const DELETE_WORK_QUERY = gql`
  mutation workDelete($id: ID!) {
    workEdit(id: $id) {
      delete
    }
  }
`;

const CREATE_CONNECTOR_QUERY = gql`
  mutation RegisterConnector($input: RegisterConnectorInput) {
    registerConnector(input: $input) {
      id
      connector_state
      name
    }
  }
`;

const LIST_CONNECTORS_QUERY = gql`
  query ListConnectors {
    connectors {
      id
      name
      active
      auto
      only_contextual
      connector_type
      connector_scope
      connector_state
      built_in
    }
  }
`;

const READ_CONNECTOR_QUERY = gql`
  query GetConnectors($id: String!) {
    connector(id: $id) {
      id
      name
      active
      auto
      only_contextual
      connector_type
      connector_scope
      connector_state
      connector_queue_details {
        messages_number
        messages_size
      }
      updated_at
      created_at
      config {
        listen
        listen_exchange
        push
        push_exchange
      }
      built_in
    }
  }
`;

const DELETE_CONNECTOR_QUERY = gql`
  mutation ConnectorDeletionMutation($id: ID!) {
    deleteConnector(id: $id)
  }
`;

const TEST_CN_ID = '5ed680de-75e2-4aa0-bec0-4e8e5a0d1695';
const TEST_CN_NAME = 'TestConnector';

beforeAll(async () => {
  const CONNECTOR_TO_CREATE = {
    input: {
      id: TEST_CN_ID,
      name: TEST_CN_NAME,
      type: 'EXTERNAL_IMPORT',
      scope: 'Observable',
      auto: true,
      only_contextual: true,
    },
  };
  const connector = await queryAsUserWithSuccess(USER_CONNECTOR, {
    query: CREATE_CONNECTOR_QUERY,
    variables: CONNECTOR_TO_CREATE,
  });
  expect(connector).not.toBeNull();
  expect(connector.data.registerConnector).not.toBeNull();
  expect(connector.data.registerConnector.name).toEqual(TEST_CN_NAME);
  expect(connector.data.registerConnector.id).toEqual(TEST_CN_ID);
});

const CREATED_CN_COUNT = 1;
const BUILT_IN_CN_COUNT = BACKGROUND_TASK_QUEUES + 2;

describe('Connector resolver standard behaviour', () => {
  let workId: string;
  it('should list all connectors', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: LIST_CONNECTORS_QUERY, variables: {} });
    expect(queryResult.data.connectors).toBeDefined();
    // currently 7 : 1 created (TestConnector) + 6 built-in connectors (4 background tasks + import csv + draft validation)
    expect(queryResult.data.connectors.length).toEqual(CREATED_CN_COUNT + BUILT_IN_CN_COUNT);
    // TestConnector created above
    expect(queryResult.data.connectors.find((c: Connector) => c.id === TEST_CN_ID)).toBeDefined();
    expect(queryResult.data.connectors.find((c: Connector) => c.id === TEST_CN_ID).name).toEqual(TEST_CN_NAME);
    // 6 built-in connectors
    expect(queryResult.data.connectors.filter((c: Connector) => c.built_in).length).toEqual(BUILT_IN_CN_COUNT);
    // check background tasks built_in connectors
    expect(queryResult.data.connectors.filter((c: Connector) => c.connector_scope?.includes(ENTITY_TYPE_BACKGROUND_TASK)).length).toEqual(BACKGROUND_TASK_QUEUES);
    // check built_in csv connector
    expect(queryResult.data.connectors.filter((c: Connector) => c.id === IMPORT_CSV_CONNECTOR.id).length).toEqual(1);
    // check built_in draft validation connector
    expect(queryResult.data.connectors.filter((c: Connector) => c.id === DRAFT_VALIDATION_CONNECTOR.id).length).toEqual(1);
  });
  it('should create work', async () => {
    const WORK_TO_CREATE = {
      connectorId: TEST_CN_ID,
      friendlyName: 'TestConnector',
    };

    const work = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: CREATE_WORK_QUERY,
      variables: WORK_TO_CREATE,
    });

    expect(work).not.toBeNull();
    expect(work.data.workAdd).not.toBeNull();
    expect(work.data.workAdd.id).not.toBeNull();
    workId = work.data.workAdd.id;
  });
  it('should list works', async () => {
    // List all works for connector
    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: LIST_WORK_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filters: [{ key: 'connector_id', values: [TEST_CN_ID] }],
          filterGroups: [],
        },
      },
    });

    expect(queryResult.data.works.edges.length).toEqual(1);
  });
  it('should update work from progress to complete', async () => {
    // Read work
    let queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.work.status).toEqual('progress');

    // Update work and declare as finished
    queryResult = await queryAsAdminWithSuccess({
      query: UPDATE_WORK_QUERY,
      variables: { id: workId, message: 'Finished', inError: false },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workEdit.toProcessed).toEqual(workId);

    // Read work and verify status
    queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.work.status).toEqual('complete');
  });
  it('should delete work', async () => {
    // Delete the work
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: DELETE_WORK_QUERY,
      variables: { id: workId },
    });

    // Verify is no longer found
    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.work).toBeNull();
  });

  it('should get connector details', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
    expect(queryResult.data.connector.connector_queue_details).toBeDefined();
    expect(queryResult.data.connector.connector_queue_details.messages_number).toBe(0);
    expect(queryResult.data.connector.connector_queue_details.messages_size).toBe(0);
  });

  it('should legacy ping still works (without connector_info)', async () => {
    const PING_CONNECTOR_LEGACY_QUERY = gql`
      mutation PingConnector($id: ID!, $state: String) {
        pingConnector(id: $id, state: $state) {
          id
        }
      }
    `;
    const state = '{"last_run": 1718010586.1741812}';
    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: PING_CONNECTOR_LEGACY_QUERY, variables: { id: TEST_CN_ID, state } });
    expect(queryResult.data.pingConnector.id).toBeDefined();
  });

  it('should store buffering data and run and terminate info from ping', async () => {
    const PING_CONNECTOR_QUERY = gql`
      mutation PingConnector($id: ID!, $state: String, $connectorInfo: ConnectorInfoInput) {
        pingConnector(id: $id, state: $state, connectorInfo:$connectorInfo) {
          id
          connector_info {
            buffering
            next_run_datetime
            last_run_datetime
            queue_messages_size
            run_and_terminate
            queue_threshold
          }
        }
      }
    `;

    const datetimeNextRun = new Date();
    const datetimeLastRun = new Date(datetimeNextRun.getTime() - 5 * 60 * 1000);

    const connectorInfo: ConnectorInfo = {
      buffering: true,
      queue_messages_size: 20.50,
      queue_threshold: 490.2,
      run_and_terminate: true,
      next_run_datetime: datetimeNextRun,
      last_run_datetime: datetimeLastRun,
    };

    const state = '{"last_run": 1718010586.1741812}';

    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: PING_CONNECTOR_QUERY, variables: { id: TEST_CN_ID, state, connectorInfo } });

    expect(queryResult.data.pingConnector).toBeDefined();
    expect(queryResult.data.pingConnector.connector_info.run_and_terminate).toBeTruthy();
    expect(queryResult.data.pingConnector.connector_info.buffering).toBeTruthy();
    expect(queryResult.data.pingConnector.connector_info.queue_messages_size).toBe(20.50);
    expect(queryResult.data.pingConnector.connector_info.queue_threshold).toBe(490.2);
    expect(queryResult.data.pingConnector.connector_info.next_run_datetime.toISOString()).toBe(datetimeNextRun.toISOString());
    expect(queryResult.data.pingConnector.connector_info.last_run_datetime.toISOString()).toBe(datetimeLastRun.toISOString());
  });
});

describe('Connector sending multiple bundles during the same multi-part work', () => {
  describe('when worker finishes all work items before connector', () => {
    it('should mark work as completed when connector calls to_processed', async () => {
      let queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: CREATE_WORK_QUERY,
        variables: {
          connectorId: TEST_CN_ID,
          friendlyName: 'TestConnectorMultipleBundles',
          isMultiPartWork: true,
        },
      });
      const workId = queryResult.data.workAdd.id;
      queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
      expect(queryResult.data.work.status).toEqual('progress');

      // Connector sends bundle #1: increase expectation count
      await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: UPDATE_WORK_ADD_EXPECTATIONS_QUERY,
        variables: { id: workId, expectations: 3 },
      });

      // Worker treats all 3 work items
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: {
        id: workId,
        error: {
          error: 'woups',
          source: 'code',
        },
      } });
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });

      // Status should still be `progress`
      queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
      expect(queryResult.data.work.status).toEqual('progress');

      // Connector sends bundle #2: increase expectation count
      await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: UPDATE_WORK_ADD_EXPECTATIONS_QUERY,
        variables: { id: workId, expectations: 2 },
      });

      // Worker treats all 2 work items
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });

      // Status should still be `progress`
      queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
      expect(queryResult.data.work.status).toEqual('progress');

      // Connector notifies backend it processed all bundles
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_QUERY, variables: {
        id: workId,
        message: 'Done',
      } });

      // Status should have changed to `complete`
      queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
      expect(queryResult.data.work.status).toEqual('complete');
      expect(queryResult.data.work.completed_number).toEqual(5);
    });
  });

  describe('when connector notifies to_processed before worker finished items', () => {
    it('should mark work as completed after worker finished last item', async () => {
      let queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: CREATE_WORK_QUERY,
        variables: {
          connectorId: TEST_CN_ID,
          friendlyName: 'TestConnectorMultipleBundles',
          isMultiPartWork: true,
        },
      });
      const workId = queryResult.data.workAdd.id;
      queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
      expect(queryResult.data.work.status).toEqual('progress');

      // Connector sends bundle #1: increase expectation count
      await queryAsAdminWithSuccess({
        query: UPDATE_WORK_ADD_EXPECTATIONS_QUERY,
        variables: { id: workId, expectations: 3 },
      });

      // Worker treats all 3 work items
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: {
        id: workId,
        error: {
          error: 'woups',
          source: 'code',
        },
      } });
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });

      // Status should still be `progress`
      queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
      expect(queryResult.data.work.status).toEqual('progress');

      // Connector sends bundle #2: increase expectation count
      await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: UPDATE_WORK_ADD_EXPECTATIONS_QUERY,
        variables: { id: workId, expectations: 2 },
      });

      // Connector notifies backend it processed all bundles
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_QUERY, variables: {
        id: workId,
        message: 'Done',
      } });

      // Status should still be `progress`
      queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
      expect(queryResult.data.work.status).toEqual('progress');

      // Worker treats all remaining items
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });

      // Status should have changed to `complete`
      queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
      expect(queryResult.data.work.status).toEqual('complete');
      expect(queryResult.data.work.completed_number).toEqual(5);
    });
  });
});

describe('Connector using the default work isMultiPartWork=false option', () => {
  it('should mark work as completed when all items are processed', async () => {
    let queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: CREATE_WORK_QUERY,
      variables: {
        connectorId: TEST_CN_ID,
        friendlyName: 'TestConnectorSinglePart',
      },
    });
    const workId = queryResult.data.workAdd.id;
    queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.work.status).toEqual('progress');

    // Add expectation count
    await queryAsAdminWithSuccess({
      query: UPDATE_WORK_ADD_EXPECTATIONS_QUERY,
      variables: { id: workId, expectations: 5 },
    });

    // Report as many expectations
    await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });
    await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });
    await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: {
      id: workId,
      error: {
        error: 'woups',
        source: 'code',
      },
    } });
    await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });

    queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
    expect(queryResult.data.work.status).toEqual('progress');

    await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_REPORT_EXPECTATION_QUERY, variables: { id: workId } });

    // Status should have changed to `complete` without the need to call `toProcessed`
    queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, { query: READ_WORK_QUERY, variables: { id: workId } });
    expect(queryResult.data.work.status).toEqual('complete');
  });
});

describe('Connector completing without actual work', () => {
  it('should mark work as completed', async () => {
    let queryResult = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: CREATE_WORK_QUERY,
      variables: {
        connectorId: TEST_CN_ID,
        friendlyName: 'TestConnectorNoWork',
      },
    });
    const workId = queryResult.data.workAdd.id;

    // Admin sees 'progress' status
    queryResult = await queryAsAdminWithSuccess({ query: READ_WORK_QUERY, variables: { id: workId } });
    expect(queryResult.data.work.status).toEqual('progress');

    // Connector notifies backend it's done
    await queryAsUserWithSuccess(USER_CONNECTOR, { query: UPDATE_WORK_QUERY, variables: {
      id: workId,
      message: 'Done',
    } });

    // Admin sees status changed to `complete`
    queryResult = await queryAsAdminWithSuccess({ query: READ_WORK_QUERY, variables: { id: workId } });
    expect(queryResult.data.work.status).toEqual('complete');
  });
});

describe('Capability checks', () => {
  it('Editor user should not be allowed to see connector details', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: READ_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
  });

  it('Participate user should not be allowed to delete connector', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: DELETE_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
  });
});

afterAll(async () => {
  // Delete the connector
  await queryAsAdminWithSuccess({ query: DELETE_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
  // Verify is no longer found
  const queryResult = await queryAsAdmin({ query: READ_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
  expect(queryResult).not.toBeNull();
  expect(queryResult.data?.connector).toBeNull();
});
