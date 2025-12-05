import { expect, it, describe, afterAll, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import { v4 as uuid } from 'uuid';
import { queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { USER_CONNECTOR } from '../../utils/testQuery';
import { waitInSec } from '../../../src/database/utils';

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
  query GetConnector($id: String!) {
    connector(id: $id) {
      id
      name
      connector_state
      connector_queue_details {
        messages_number
        messages_size
      }
    }
  }
`;

const RESET_CONNECTOR_QUERY = gql`
  mutation ResetStateConnector($id: ID!) {
    resetStateConnector(id: $id) {
      id
      connector_state
      connector_queue_details {
        messages_number
        messages_size
      }
    }
  }
`;

const DELETE_CONNECTOR_QUERY = gql`
  mutation ConnectorDeletionMutation($id: ID!) {
    deleteConnector(id: $id)
  }
`;

const TEST_RESET_CN_ID = uuid();
const TEST_RESET_CN_NAME = 'TestResetConnector';

describe('Connector reset state functionality', () => {
  beforeAll(async () => {
    const CONNECTOR_TO_CREATE = {
      input: {
        id: TEST_RESET_CN_ID,
        name: TEST_RESET_CN_NAME,
        type: 'EXTERNAL_IMPORT',
        scope: 'Observable',
        auto: true,
        only_contextual: false,
      },
    };
    const connector = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
      query: CREATE_CONNECTOR_QUERY,
      variables: CONNECTOR_TO_CREATE,
    });
    expect(connector).not.toBeNull();
    expect(connector.data.registerConnector).not.toBeNull();
    expect(connector.data.registerConnector.id).toEqual(TEST_RESET_CN_ID);
    
    await waitInSec(1);
  });

  it('should fetch connector with queue details from RabbitMQ API', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
      query: READ_CONNECTOR_QUERY,
      variables: { id: TEST_RESET_CN_ID },
    });

    expect(queryResult.data.connector).toBeDefined();
    expect(queryResult.data.connector.id).toEqual(TEST_RESET_CN_ID);
    expect(queryResult.data.connector.connector_queue_details).toBeDefined();
    expect(typeof queryResult.data.connector.connector_queue_details.messages_number).toBe('number');
    expect(typeof queryResult.data.connector.connector_queue_details.messages_size).toBe('number');
    expect(queryResult.data.connector.connector_queue_details.messages_number).toBeGreaterThanOrEqual(0);
    expect(queryResult.data.connector.connector_queue_details.messages_size).toBeGreaterThanOrEqual(0);
  });

  it('should return consistent queue details across multiple API calls', async () => {
    
    const firstFetch = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
      query: READ_CONNECTOR_QUERY,
      variables: { id: TEST_RESET_CN_ID },
    });

    await waitInSec(0.5);

    const secondFetch = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
      query: READ_CONNECTOR_QUERY,
      variables: { id: TEST_RESET_CN_ID },
    });

    expect(firstFetch.data.connector.connector_queue_details).toBeDefined();
    expect(secondFetch.data.connector.connector_queue_details).toBeDefined();
    
    expect(firstFetch.data.connector.connector_queue_details.messages_number)
      .toEqual(secondFetch.data.connector.connector_queue_details.messages_number);
    expect(firstFetch.data.connector.connector_queue_details.messages_size)
      .toEqual(secondFetch.data.connector.connector_queue_details.messages_size);
  });

  it('should reset connector state and clear queue', async () => {
    const resetResult = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
      query: RESET_CONNECTOR_QUERY,
      variables: { id: TEST_RESET_CN_ID },
    });

    expect(resetResult.data.resetStateConnector).toBeDefined();
    expect(resetResult.data.resetStateConnector.id).toEqual(TEST_RESET_CN_ID);
    expect(resetResult.data.resetStateConnector.connector_state).toBeNull();
    
    expect(resetResult.data.resetStateConnector.connector_queue_details).toBeDefined();

    await waitInSec(2);

    const verifyResult = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
      query: READ_CONNECTOR_QUERY,
      variables: { id: TEST_RESET_CN_ID },
    });

    expect(verifyResult.data.connector.connector_queue_details.messages_number).toEqual(0);
    expect(verifyResult.data.connector.connector_queue_details.messages_size).toEqual(0);
  });

  it('should handle rapid successive API calls without errors', async () => {
 
    const rapidCalls = await Promise.all([
      queryAsUserWithSuccess(USER_CONNECTOR.client, {
        query: READ_CONNECTOR_QUERY,
        variables: { id: TEST_RESET_CN_ID },
      }),
      queryAsUserWithSuccess(USER_CONNECTOR.client, {
        query: READ_CONNECTOR_QUERY,
        variables: { id: TEST_RESET_CN_ID },
      }),
      queryAsUserWithSuccess(USER_CONNECTOR.client, {
        query: READ_CONNECTOR_QUERY,
        variables: { id: TEST_RESET_CN_ID },
      }),
    ]);

    rapidCalls.forEach((result) => {
      expect(result.data.connector).toBeDefined();
      expect(result.data.connector.connector_queue_details).toBeDefined();
      expect(typeof result.data.connector.connector_queue_details.messages_number).toBe('number');
    });

    const firstCount = rapidCalls[0].data.connector.connector_queue_details.messages_number;
    rapidCalls.forEach((result) => {
      expect(result.data.connector.connector_queue_details.messages_number).toEqual(firstCount);
    });
  });

  afterAll(async () => {
    await queryAsUserWithSuccess(USER_CONNECTOR.client, {
      query: DELETE_CONNECTOR_QUERY,
      variables: { id: TEST_RESET_CN_ID },
    });
  });
});