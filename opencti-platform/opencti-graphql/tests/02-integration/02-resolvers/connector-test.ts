import { expect, it, describe, afterAll, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, USER_CONNECTOR, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import type { ConnectorInfo } from '../../../src/generated/graphql';

const CREATE_WORK_QUERY = gql`
  mutation workAdd($connectorId: String!, $friendlyName: String) {
    workAdd(connectorId: $connectorId, friendlyName: $friendlyName) {
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

beforeAll(async () => {
  const CONNECTOR_TO_CREATE = {
    input: {
      id: TEST_CN_ID,
      name: 'TestConnector',
      type: 'EXTERNAL_IMPORT',
      scope: 'Observable',
      auto: true,
      only_contextual: true,
    },
  };
  const connector = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
    query: CREATE_CONNECTOR_QUERY,
    variables: CONNECTOR_TO_CREATE,
  });
  expect(connector).not.toBeNull();
  expect(connector.data.registerConnector).not.toBeNull();
  expect(connector.data.registerConnector.name).toEqual('TestConnector');
  expect(connector.data.registerConnector.id).toEqual(TEST_CN_ID);
});

describe('Connector resolver standard behaviour', () => {
  let workId: string;
  it('should create work', async () => {
    const WORK_TO_CREATE = {
      connectorId: TEST_CN_ID,
      friendlyName: 'TestConnector',
    };

    const work = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
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
    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
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
    let queryResult = await queryAsUserWithSuccess(USER_CONNECTOR.client, { query: READ_WORK_QUERY, variables: { id: workId } });
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
    queryResult = await queryAsUserWithSuccess(USER_CONNECTOR.client, { query: READ_WORK_QUERY, variables: { id: workId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.work.status).toEqual('complete');
  });
  it('should delete work', async () => {
    // Delete the work
    await queryAsUserWithSuccess(USER_CONNECTOR.client, {
      query: DELETE_WORK_QUERY,
      variables: { id: workId },
    });

    // Verify is no longer found
    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR.client, { query: READ_WORK_QUERY, variables: { id: workId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.work).toBeNull();
  });

  it('should get connector details', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR.client, { query: READ_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
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
    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR.client, { query: PING_CONNECTOR_LEGACY_QUERY, variables: { id: TEST_CN_ID, state } });
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

    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR.client, { query: PING_CONNECTOR_QUERY, variables: { id: TEST_CN_ID, state, connectorInfo } });

    expect(queryResult.data.pingConnector).toBeDefined();
    expect(queryResult.data.pingConnector.connector_info.run_and_terminate).toBeTruthy();
    expect(queryResult.data.pingConnector.connector_info.buffering).toBeTruthy();
    expect(queryResult.data.pingConnector.connector_info.queue_messages_size).toBe(20.50);
    expect(queryResult.data.pingConnector.connector_info.queue_threshold).toBe(490.2);
    expect(queryResult.data.pingConnector.connector_info.next_run_datetime).toBe(datetimeNextRun.toISOString());
    expect(queryResult.data.pingConnector.connector_info.last_run_datetime).toBe(datetimeLastRun.toISOString());
  });
});

describe('Capability checks', () => {
  it('Editor user should not be allowed to see connector details', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, { query: READ_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
  });

  it('Participate user should not be allowed to delete connector', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, { query: DELETE_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
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
