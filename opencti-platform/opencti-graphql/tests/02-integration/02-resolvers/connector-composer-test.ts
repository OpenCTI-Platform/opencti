import { expect, it, describe, afterAll, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import { v4 as uuidv4 } from 'uuid';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { USER_CONNECTOR, USER_EDITOR } from '../../utils/testQuery';
import { wait } from '../../../src/database/utils';
import { XTMComposerMock } from '../../utils/XTMComposerMock';
import type { ApiConnector } from '../../utils/XTMComposerMock';
import { catalogHelper } from '../../utils/catalogHelper';

const TEST_COMPOSER_ID = uuidv4();
const TEST_USER_CONNECTOR_ID: string = USER_CONNECTOR.id; // Initialize with default value
const TEST_COMPOSER_PUBLIC_KEY = '-----BEGIN RSA PUBLIC KEY-----MIICCgKCAgEAk8V1xvej71cJhH+XAVwJKXkpM90fM8gf9jhq5t2SKDnMhGfl7bSNSRKEN6zUea3F4Q635SCK0klAh69J2wh1LakPb5Z/lRv5n/OA3QnIN'
    + 'NbQwnDD2tjMoVoR/fW/oe8AG5CvgES0kLx/wfVoxUPpWyOTtWvtIjJH+Cyrj4as4lICaeci6AdjRfhR/syVaErflTEdJyps2g5DA3p8H9f+IOTxOK8dCBYWGPHLkgEXhz8Pc6mmIq7IYHeYMUXHOokrjCKiw1s59NAJvhdSmYP15Udac1QNG'
    + 'LTIsV8IvWvYWmUmOWUOTXAgy/sX1IuH+mt3yjmPzfScaSwPkecLkaGdUIecHZGyDHy+fJsb8vmj3NWr6MiehTFLs+UKyp+VPLSzxT29Umd/ZkqoYtMH0Fj/vIptxg7E5G/YQZtwB23OXPEZ2eC6cUKXwZXext+CS7Gdp8HoQn4Z7lpSQT'
    + 'h6lim/Olx5SpTSpXhFE8lTjT1MlbXyeEwBRFYpb/BjthsHM3d7pRdpJL613ZzMjEgJnE5dwAX7nlTdAldChLbA7U9Hw254NLZcO301j2YHcU1JiGHTtMO7nOrVFy7FIA5HS2kKRW8dWMm7C3sVmuWEjmydsCQZIvHmPTvkTE4YnEP1U'
    + 'ZuNczinaR08oW/CBuajmNqJsCsmg6m9ThuxizJh71NzcNMCAwEAAQ==-----END RSA PUBLIC KEY-----';

// Test configuration
// The goal is to achieve a 1:1 behavior match between XTMComposerMock and XTMComposer.
// This enables authentic integration testing (assuming the XTM Composer is available in the CI) without the need to rewrite the test suite.
const FORCE_POLLING = true; // Set to true for faster tests, false for realistic XTM Composer behavior

// Mutations
const REGISTER_CONNECTORS_MANAGER_MUTATION = gql`
    mutation RegisterConnectorsManager($input: RegisterConnectorsManagerInput!) {
        registerConnectorsManager(input: $input) {
            id
            public_key
            name
            last_sync_execution
            active
            about_version
        }
    }
`;

const UPDATE_CONNECTOR_MANAGER_STATUS_MUTATION = gql`
    mutation UpdateConnectorManagerStatus($input: UpdateConnectorManagerStatusInput!) {
        updateConnectorManagerStatus(input: $input) {
            id
            public_key
            last_sync_execution
        }
    }
`;

const ADD_MANAGED_CONNECTOR_MUTATION = gql`
    mutation ManagedConnectorAdd($input: AddManagedConnectorInput!) {
        managedConnectorAdd(input: $input) {
            id
            name
            connector_user_id
            manager_contract_image
            manager_requested_status
            manager_contract_configuration {
                key
                value
            }
            manager_contract_hash
        }
    }
`;

const EDIT_MANAGED_CONNECTOR_MUTATION = gql`
    mutation ManagedConnectorEdit($input: EditManagedConnectorInput!) {
        managedConnectorEdit(input: $input) {
            id
            name
            connector_user_id
            manager_contract_configuration {
                key
                value
            }
        }
    }
`;

const UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION = gql`
    mutation UpdateConnectorRequestedStatus($input: RequestConnectorStatusInput!) {
        updateConnectorRequestedStatus(input: $input) {
            id
            manager_requested_status
        }
    }
`;

const UPDATE_CONNECTOR_LOGS_MUTATION = gql`
    mutation UpdateConnectorLogs($input: LogsConnectorStatusInput!) {
        updateConnectorLogs(input: $input)
    }
`;

const DELETE_CONNECTOR_MUTATION = gql`
    mutation ConnectorDeletionMutation($id: ID!) {
        deleteConnector(id: $id)
    }
`;

// Queries
const CONNECTOR_MANAGER_QUERY = gql`
    query ConnectorManager($managerId: ID!) {
        connectorManager(managerId: $managerId) {
            id
            name
            public_key
            last_sync_execution
            active
        }
    }
`;

const CONNECTOR_MANAGERS_QUERY = gql`
    query ConnectorManagers {
        connectorManagers {
            id
            name
            public_key
            active
        }
    }
`;

const CONNECTOR_LOGS_QUERY = gql`
    query GetConnectorLogs($id: String!) {
        connector(id: $id) {
            id
            manager_connector_logs
        }
    }
`;

const ipinfoProperties = {
  CONNECTOR_LISTEN_PROTOCOL_API_PORT: 0,
  CONNECTOR_LISTEN_PROTOCOL_API_SSL: false
};

const ipinfoListProperties = [
  { key: 'CONNECTOR_LISTEN_PROTOCOL_API_PORT', value: ['0'] },
  { key: 'CONNECTOR_LISTEN_PROTOCOL_API_SSL', value: ['false'] }
];

describe('Connector Composer and Managed Connectors', () => {
  // Track all created resources
  const createdConnectorIds = new Set<string>();
  let xtmComposer: XTMComposerMock;

  // Initialize XTM Composer mock
  beforeAll(async () => {
    xtmComposer = new XTMComposerMock({
      operationDelay: 100, // Faster for testing
      failureRate: 0, // No failures for basic tests
      executeSchedule: 1, // Poll every 1 second for tests
    }, null);

    if (!FORCE_POLLING) {
      // Start the orchestration loop only if not forcing polling
      await xtmComposer.startOrchestration();
    }
  });

  describe('Connector Composer operations', () => {
    it('should register a new connector composer', async () => {
      const input = {
        id: TEST_COMPOSER_ID,
        name: 'Test Composer',
        public_key: TEST_COMPOSER_PUBLIC_KEY,
      };

      const result = await queryAsAdminWithSuccess({
        query: REGISTER_CONNECTORS_MANAGER_MUTATION,
        variables: { input }
      });

      expect(result.data).toBeDefined();
      expect(result.data?.registerConnectorsManager).not.toBeNull();
      expect(result.data?.registerConnectorsManager.id).toEqual(TEST_COMPOSER_ID);
      expect(result.data?.registerConnectorsManager.name).toEqual('Test Composer');
      expect(result.data?.registerConnectorsManager.public_key).toEqual(TEST_COMPOSER_PUBLIC_KEY);
      expect(result.data?.registerConnectorsManager.last_sync_execution).not.toBeNull();
    });

    it('should update existing connector composer', async () => {
      const input = {
        id: TEST_COMPOSER_ID,
        name: 'Test Composer Updated',
        public_key: TEST_COMPOSER_PUBLIC_KEY,
      };

      const result = await queryAsAdminWithSuccess({
        query: REGISTER_CONNECTORS_MANAGER_MUTATION,
        variables: { input }
      });

      expect(result.data).toBeDefined();
      expect(result.data?.registerConnectorsManager.name).toEqual('Test Composer Updated');
      expect(result.data?.registerConnectorsManager.public_key).toEqual(TEST_COMPOSER_PUBLIC_KEY);
    });

    it('should update connector composer status', async () => {
      const previousResult = await queryAsAdminWithSuccess({
        query: CONNECTOR_MANAGER_QUERY,
        variables: { managerId: TEST_COMPOSER_ID }
      });
      expect(previousResult.data).toBeDefined();
      const previousSync = previousResult.data?.connectorManager.last_sync_execution;

      // Wait a bit to ensure timestamp difference
      await wait(10);

      const result = await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_MANAGER_STATUS_MUTATION,
        variables: { input: { id: TEST_COMPOSER_ID } }
      });

      expect(result.data).toBeDefined();
      expect(result.data?.updateConnectorManagerStatus.id).toEqual(TEST_COMPOSER_ID);
      expect(result.data?.updateConnectorManagerStatus.last_sync_execution).not.toEqual(previousSync);
    });

    it('should get connector composer by id', async () => {
      const result = await queryAsAdminWithSuccess({
        query: CONNECTOR_MANAGER_QUERY,
        variables: { managerId: TEST_COMPOSER_ID }
      });

      expect(result.data).toBeDefined();
      expect(result.data?.connectorManager).not.toBeNull();
      expect(result.data?.connectorManager.id).toEqual(TEST_COMPOSER_ID);
      expect(result.data?.connectorManager.name).toEqual('Test Composer Updated');
      expect(result.data?.connectorManager.active).toBeDefined();
    });

    it('should list all connector composers', async () => {
      const result = await queryAsAdminWithSuccess({
        query: CONNECTOR_MANAGERS_QUERY,
        variables: {}
      });

      expect(result.data).toBeDefined();
      expect(result.data?.connectorManagers).toBeDefined();
      const composer = result.data?.connectorManagers.find((m: any) => m.id === TEST_COMPOSER_ID);
      expect(composer).toBeDefined();
      expect(composer.name).toEqual('Test Composer Updated');
    });
  });

  describe('Managed Connector operations with XTM Composer', () => {
    let deploymentConnectorId: string;

    it('should deploy a managed connector', async () => {
      // Get test connector from catalog
      const testConnector = catalogHelper.getTestSafeConnector();
      const catalogId = catalogHelper.getCatalogId();

      // First create a managed connector
      const createInput = {
        name: 'Connector for Deployment Test',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: catalogId,
        manager_contract_image: testConnector.container_image,
        manager_contract_configuration: catalogHelper.getMinimalConfig(testConnector, {
          IPINFO_TOKEN: 'deployment-test-token',
          ...ipinfoProperties
        })
      };

      const createResult = await queryAsAdminWithSuccess({
        query: ADD_MANAGED_CONNECTOR_MUTATION,
        variables: { input: createInput }
      });

      expect(createResult.data).toBeDefined();
      deploymentConnectorId = createResult.data?.managedConnectorAdd.id;
      createdConnectorIds.add(deploymentConnectorId);

      // Request deployment through platform
      const deployInput = {
        id: deploymentConnectorId,
        status: 'starting'
      };

      const deployResult = await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
        variables: { input: deployInput }
      });

      expect(deployResult.data).toBeDefined();
      expect(deployResult.data?.updateConnectorRequestedStatus.manager_requested_status).toEqual('starting');

      // Wait for XTM Composer to detect and deploy the connector
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(1500); // Wait for at least one polling cycle
      }

      // Verify the connector is now started
      const GET_CONNECTOR_QUERY = gql`
        query GetConnector($id: String!) {
          connector(id: $id) {
            id
            manager_current_status
          }
        }
      `;

      const connectorResult = await queryAsAdminWithSuccess({
        query: GET_CONNECTOR_QUERY,
        variables: { id: deploymentConnectorId }
      });

      expect(connectorResult.data?.connector.manager_current_status).toEqual('started');
    });

    it('should start a deployed connector', async () => {
      // First ensure connector is stopped
      const stopInput = {
        id: deploymentConnectorId,
        status: 'stopping'
      };

      await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
        variables: { input: stopInput }
      });

      // Wait for XTM Composer to detect and stop
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(1500);
      }

      // Request start through platform
      const startRequestInput = {
        id: deploymentConnectorId,
        status: 'starting'
      };

      const startResult = await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
        variables: { input: startRequestInput }
      });

      expect(startResult.data).toBeDefined();
      expect(startResult.data?.updateConnectorRequestedStatus.manager_requested_status).toEqual('starting');

      // Wait for XTM Composer to detect and start the connector
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(1500);
      }

      // Verify status
      const GET_CONNECTOR_QUERY = gql`
        query GetConnector($id: String!) {
          connector(id: $id) {
            id
            manager_current_status
          }
        }
      `;

      const connectorResult = await queryAsAdminWithSuccess({
        query: GET_CONNECTOR_QUERY,
        variables: { id: deploymentConnectorId }
      });

      expect(connectorResult.data?.connector.manager_current_status).toEqual('started');
    });

    it('should stop a running connector', async () => {
      // Request stop through platform
      const stopRequestInput = {
        id: deploymentConnectorId,
        status: 'stopping'
      };

      const stopResult = await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
        variables: { input: stopRequestInput }
      });

      expect(stopResult.data).toBeDefined();
      expect(stopResult.data?.updateConnectorRequestedStatus.manager_requested_status).toEqual('stopping');

      // Wait for XTM Composer to detect and stop the connector
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(1500);
      }

      // Verify status
      const GET_CONNECTOR_QUERY = gql`
        query GetConnector($id: String!) {
          connector(id: $id) {
            id
            manager_current_status
          }
        }
      `;

      const connectorResult = await queryAsAdminWithSuccess({
        query: GET_CONNECTOR_QUERY,
        variables: { id: deploymentConnectorId }
      });

      expect(connectorResult.data?.connector.manager_current_status).toEqual('stopped');
    });

    it('should restart a connector', async () => {
      // Request stop through platform
      const stopRequestInput = {
        id: deploymentConnectorId,
        status: 'stopping'
      };

      await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
        variables: { input: stopRequestInput }
      });

      // Wait for XTM Composer to process stop
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(1500);
      }

      // Verify stopped
      const GET_CONNECTOR_QUERY = gql`
        query GetConnector($id: String!) {
          connector(id: $id) {
            id
            manager_current_status
          }
        }
      `;

      let connectorResult = await queryAsAdminWithSuccess({
        query: GET_CONNECTOR_QUERY,
        variables: { id: deploymentConnectorId }
      });

      expect(connectorResult.data?.connector.manager_current_status).toEqual('stopped');

      // Request start through platform
      const startRequestInput = {
        id: deploymentConnectorId,
        status: 'starting'
      };

      await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
        variables: { input: startRequestInput }
      });

      // Wait for XTM Composer to restart
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(1500);
      }

      // Verify status
      connectorResult = await queryAsAdminWithSuccess({
        query: GET_CONNECTOR_QUERY,
        variables: { id: deploymentConnectorId }
      });

      expect(connectorResult.data?.connector.manager_current_status).toEqual('started');
    });

    it('should change/update the connector log level (e.g., DEBUG, INFO, WARN, ERROR)', async () => {
      // Get test connector from catalog
      const testConnector = catalogHelper.getTestSafeConnector();
      const catalogId = catalogHelper.getCatalogId();

      // Create a dedicated connector for this test
      const createInput = {
        name: 'Log Level Test Connector',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: catalogId,
        manager_contract_image: testConnector.container_image,
        manager_contract_configuration: catalogHelper.getMinimalConfig(testConnector, {
          IPINFO_TOKEN: 'log-level-test-token',
          CONNECTOR_LOG_LEVEL: 'info', // Initial log level
          ...ipinfoProperties
        })
      };

      const createResult = await queryAsAdminWithSuccess({
        query: ADD_MANAGED_CONNECTOR_MUTATION,
        variables: { input: createInput }
      });

      expect(createResult.data).toBeDefined();
      const logLevelConnectorId = createResult.data?.managedConnectorAdd.id;
      createdConnectorIds.add(logLevelConnectorId);

      // Start the connector
      await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
        variables: { input: { id: logLevelConnectorId, status: 'starting' } }
      });

      // Wait for XTM Composer to deploy
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(1500);
      }

      // Get current configuration to preserve other settings
      const GET_CONNECTOR_QUERY = gql`
        query GetConnector($id: String!) {
          connector(id: $id) {
            id
            manager_current_status
            manager_contract_configuration {
              key
              value
            }
          }
        }
      `;

      const connectorResult = await queryAsAdminWithSuccess({
        query: GET_CONNECTOR_QUERY,
        variables: { id: logLevelConnectorId }
      });

      expect(connectorResult.data?.connector.manager_current_status).toEqual('started');

      // Update the connector configuration with a new log level (change from 'info' to 'debug')
      const updateInput = {
        id: logLevelConnectorId,
        name: 'Log Level Test Connector',
        connector_user_id: TEST_USER_CONNECTOR_ID,
        manager_contract_configuration: [
          { key: 'IPINFO_TOKEN', value: ['log-level-test-token'] },
          { key: 'CONNECTOR_LOG_LEVEL', value: ['debug'] }, // Changed from 'info' to 'debug'
          ...ipinfoListProperties
        ]
      };

      const updateResult = await queryAsAdminWithSuccess({
        query: EDIT_MANAGED_CONNECTOR_MUTATION,
        variables: { input: updateInput }
      });

      expect(updateResult.data).toBeDefined();
      expect(updateResult.data?.managedConnectorEdit).toBeDefined();

      // Wait for XTM Composer to detect the configuration change and redeploy
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(2000); // Wait a bit longer for configuration change detection
      }

      // Query the connector logs to verify the redeploy happened
      const logsResult = await queryAsAdminWithSuccess({
        query: CONNECTOR_LOGS_QUERY,
        variables: { id: logLevelConnectorId }
      });

      expect(logsResult.data).toBeDefined();
      const logs = logsResult.data?.connector.manager_connector_logs || [];

      // Verify logs contain evidence of configuration change and redeploy
      const logStrings = logs.join('\n');
      expect(logStrings).toContain('[XTM-Composer] Configuration changed, redeploying connector...');
      expect(logStrings).toContain('[XTM-Composer] Connector redeployed successfully');

      // Verify the connector is still running after the redeploy
      const statusResult = await queryAsAdminWithSuccess({
        query: GET_CONNECTOR_QUERY,
        variables: { id: logLevelConnectorId }
      });
      expect(statusResult.data?.connector.manager_current_status).toEqual('started');

      // Verify the new log level is applied
      const newConfig = statusResult.data?.connector.manager_contract_configuration || [];
      const logLevelConfig = newConfig.find((c: any) => c.key === 'CONNECTOR_LOG_LEVEL');
      expect(logLevelConfig?.value).toEqual('debug');

      // Test changing to another log level (ERROR)
      const updateInput2 = {
        id: logLevelConnectorId,
        name: 'Log Level Test Connector',
        connector_user_id: TEST_USER_CONNECTOR_ID,
        manager_contract_configuration: [
          { key: 'IPINFO_TOKEN', value: ['log-level-test-token'] },
          { key: 'CONNECTOR_LOG_LEVEL', value: ['error'] }, // Changed from 'debug' to 'error'
          ...ipinfoListProperties
        ]
      };

      await queryAsAdminWithSuccess({
        query: EDIT_MANAGED_CONNECTOR_MUTATION,
        variables: { input: updateInput2 }
      });

      // Wait for XTM Composer to detect the configuration change again
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(2000);
      }

      // Query logs again
      const logsResult2 = await queryAsAdminWithSuccess({
        query: CONNECTOR_LOGS_QUERY,
        variables: { id: logLevelConnectorId }
      });

      const logs2 = logsResult2.data?.connector.manager_connector_logs || [];
      const logStrings2 = logs2.join('\n');

      // Verify the second configuration change triggered a redeploy
      expect(logStrings2).toContain('[XTM-Composer] Configuration changed, redeploying connector...');
      expect(logStrings2).toContain('[XTM-Composer] Connector redeployed successfully');

      // Test updating only the name without changing configuration (should not redeploy)
      const updateInput3 = {
        id: logLevelConnectorId,
        name: 'Log Level Test Connector - Updated Name Only',
        connector_user_id: TEST_USER_CONNECTOR_ID,
        manager_contract_configuration: [
          { key: 'IPINFO_TOKEN', value: ['log-level-test-token'] },
          { key: 'CONNECTOR_LOG_LEVEL', value: ['error'] }, // Same log level as before
          ...ipinfoListProperties
        ]
      };

      // Clear logs before the name-only update
      await wait(100);

      await queryAsAdminWithSuccess({
        query: EDIT_MANAGED_CONNECTOR_MUTATION,
        variables: { input: updateInput3 }
      });

      // Wait for XTM Composer to check configuration
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(2000);
      }

      // Query logs one more time
      const logsResult3 = await queryAsAdminWithSuccess({
        query: CONNECTOR_LOGS_QUERY,
        variables: { id: logLevelConnectorId }
      });

      const logs3 = logsResult3.data?.connector.manager_connector_logs || [];

      // Count occurrences of redeploys - should only have the two from configuration changes
      const allLogStrings = logs3.join('\n');
      const redeployCount = (allLogStrings.match(/Connector redeployed successfully/g) || []).length;
      expect(redeployCount).toBe(2); // Only the two previous configuration changes
    });

    it('should delete a managed connector deployment', async () => {
      // First ensure connector is stopped
      const stopRequestInput = {
        id: deploymentConnectorId,
        status: 'stopping'
      };

      await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
        variables: { input: stopRequestInput }
      });

      // Wait for XTM Composer to stop the connector
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(1500);
      }

      // Now delete the connector
      const deleteResult = await queryAsAdminWithSuccess({
        query: DELETE_CONNECTOR_MUTATION,
        variables: { id: deploymentConnectorId }
      });

      expect(deleteResult.data).toBeDefined();
      expect(deleteResult.data?.deleteConnector).toEqual(deploymentConnectorId);

      // Remove from tracking set since it's been deleted
      createdConnectorIds.delete(deploymentConnectorId);

      // Verify deletion
      const GET_CONNECTOR_QUERY = gql`
        query GetConnector($id: String!) {
          connector(id: $id) {
            id
          }
        }
      `;

      const verifyResult = await queryAsAdminWithSuccess({
        query: GET_CONNECTOR_QUERY,
        variables: { id: deploymentConnectorId }
      });

      expect(verifyResult.data?.connector).toBeNull();
    });
  });

  describe('XTM Composer GraphQL calls coverage', () => {
    let testConnectorId: string;

    beforeAll(async () => {
      // Get test connector from catalog
      const testConnector = catalogHelper.getTestSafeConnector();
      const catalogId = catalogHelper.getCatalogId();

      // Create a test connector for this suite
      const createInput = {
        name: 'XTM Composer Test Connector',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: catalogId,
        manager_contract_image: testConnector.container_image,
        manager_contract_configuration: catalogHelper.getMinimalConfig(testConnector, {
          IPINFO_TOKEN: 'xtm-test-token',
          ...ipinfoProperties
        })
      };

      const createResult = await queryAsAdminWithSuccess({
        query: ADD_MANAGED_CONNECTOR_MUTATION,
        variables: { input: createInput }
      });

      testConnectorId = createResult.data?.managedConnectorAdd.id;
      createdConnectorIds.add(testConnectorId);
    });

    it('should test updateConnectorLogs GraphQL call', async () => {
      // Create a mock connector object for the logs method
      const mockConnector: ApiConnector = {
        id: testConnectorId,
        name: 'XTM Composer Test Connector',
        image: 'opencti/connector-ipinfo',
        contractHash: 'test-hash',
        requestedStatus: 'started',
        contractConfiguration: []
      };

      // Deploy the connector to create a container (required for logs method)
      await xtmComposer.deploy(mockConnector);

      // Use the logs method which will generate logs and call updateConnectorLogs
      const generatedLogs = await xtmComposer.logs(mockConnector, 5);

      // Verify logs were generated
      expect(generatedLogs).toBeDefined();
      expect(generatedLogs.length).toBe(5);
      expect(generatedLogs[0]).toContain('Connector XTM Composer Test Connector processing...');

      // Query the connector to retrieve the stored logs
      const logsResult = await queryAsAdminWithSuccess({
        query: CONNECTOR_LOGS_QUERY,
        variables: { id: testConnectorId }
      });

      // Verify the logs were stored and can be retrieved
      expect(logsResult.data).toBeDefined();
      expect(logsResult.data?.connector).toBeDefined();
      expect(logsResult.data?.connector.manager_connector_logs).toBeDefined();
      expect(Array.isArray(logsResult.data?.connector.manager_connector_logs)).toBe(true);
      expect(logsResult.data?.connector.manager_connector_logs.length).toBeGreaterThan(0);

      // Verify the retrieved logs match what was generated
      const retrievedLogs = logsResult.data?.connector.manager_connector_logs;
      expect(retrievedLogs).toEqual(expect.arrayContaining(generatedLogs));
    });

    it('should test updateConnectorCurrentStatus GraphQL call', async () => {
      // Test various status transitions
      const statuses = ['started', 'stopped'];

      await Promise.all(
        statuses.map(async (status) => {
          const result = await xtmComposer.updateConnectorCurrentStatus(testConnectorId, status);
          expect(result).toBeDefined();
          expect(result.id).toEqual(testConnectorId);
          expect(result.manager_current_status).toEqual(status);
        })
      );
    });

    it('should test connectorsForManagers GraphQL call', async () => {
      const connectors = await xtmComposer.getConnectorsForManagers();

      expect(connectors).toBeDefined();
      expect(Array.isArray(connectors)).toBe(true);

      const testConnector = connectors.find((c: any) => c.id === testConnectorId);
      expect(testConnector).toBeDefined();
      expect(testConnector.name).toEqual('XTM Composer Test Connector');
      // Split image name to ignore version
      const [imageName] = testConnector.manager_contract_image.split(':');
      expect(imageName).toEqual('opencti/connector-ipinfo');

      expect(testConnector.manager_requested_status).toBeDefined();
      expect(testConnector.manager_current_status).toBeDefined();
    });

    it('should handle concurrent XTM Composer operations', async () => {
      // Get test connector from catalog
      const testConnector = catalogHelper.getTestSafeConnector();
      const catalogId = catalogHelper.getCatalogId();

      // Create multiple connectors
      const connectorIds: string[] = [];

      const connectorPromises = Array.from({ length: 3 }, (_, i) => {
        const createInput = {
          name: `Concurrent Test Connector ${i}`,
          user_id: TEST_USER_CONNECTOR_ID,
          catalog_id: catalogId,
          manager_contract_image: testConnector.container_image,
          manager_contract_configuration: catalogHelper.getMinimalConfig(testConnector, {
            IPINFO_TOKEN: `concurrent-token-${i}`,
            ...ipinfoProperties
          })
        };

        return queryAsAdminWithSuccess({
          query: ADD_MANAGED_CONNECTOR_MUTATION,
          variables: { input: createInput }
        });
      });

      const results = await Promise.all(connectorPromises);
      results.forEach((result) => {
        const id = result.data?.managedConnectorAdd.id;
        connectorIds.push(id);
        createdConnectorIds.add(id);
      });

      // Request all connectors to start
      await Promise.all(
        connectorIds.map((id) => queryAsAdminWithSuccess({
          query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
          variables: { input: { id, status: 'starting' } }
        }))
      );

      // Wait for XTM Composer to process all connectors
      if (FORCE_POLLING) {
        await xtmComposer.runOrchestrationCycle();
      } else {
        await wait(2000); // Wait a bit longer for multiple connectors
      }

      // Verify all connectors are started
      const GET_CONNECTOR_QUERY = gql`
        query GetConnector($id: String!) {
          connector(id: $id) {
            id
            manager_current_status
          }
        }
      `;

      await Promise.all(
        connectorIds.map(async (id) => {
          const connectorResult = await queryAsAdminWithSuccess({
            query: GET_CONNECTOR_QUERY,
            variables: { id }
          });
          expect(connectorResult.data?.connector.manager_current_status).toEqual('started');
        })
      );
    });
  });

  describe('Managed Connector operations', () => {
    let managedConnectorId: string;

    it('should fail to add managed connector with invalid image', async () => {
      const catalogId = catalogHelper.getCatalogId();

      const input = {
        name: 'Test Managed Connector',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: catalogId,
        manager_contract_image: 'invalid-image',
        manager_contract_configuration: []
      };

      try {
        await queryAsAdminWithSuccess({
          query: ADD_MANAGED_CONNECTOR_MUTATION,
          variables: { input }
        });
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it('should add a new managed connector using IpInfo catalog', async () => {
      // Get test connector from catalog
      const testConnector = catalogHelper.getTestSafeConnector();
      const catalogId = catalogHelper.getCatalogId();

      const input = {
        name: 'Test IpInfo Connector',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: catalogId,
        manager_contract_image: testConnector.container_image,
        manager_contract_configuration: catalogHelper.getMinimalConfig(testConnector, {
          IPINFO_TOKEN: 'test-token-123',
          ...ipinfoProperties
        })
      };

      const result = await queryAsAdminWithSuccess({
        query: ADD_MANAGED_CONNECTOR_MUTATION,
        variables: { input }
      });

      expect(result.data).toBeDefined();
      managedConnectorId = result.data?.managedConnectorAdd.id;
      createdConnectorIds.add(managedConnectorId);
      expect(result.data?.managedConnectorAdd).not.toBeNull();
      expect(result.data?.managedConnectorAdd.name).toEqual('Test IpInfo Connector');
      expect(result.data?.managedConnectorAdd.connector_user_id).toBeDefined();
      expect(result.data?.managedConnectorAdd.manager_requested_status).toEqual('stopped');
      expect(result.data?.managedConnectorAdd.manager_contract_hash).toBeDefined();
      expect(result.data?.managedConnectorAdd.manager_contract_configuration).toBeDefined();
      expect(result.data?.managedConnectorAdd.manager_contract_configuration.length).toBeGreaterThan(0);
    });

    it('should edit managed connector', async () => {
      const input = {
        id: managedConnectorId,
        name: 'Updated IpInfo Connector',
        connector_user_id: TEST_USER_CONNECTOR_ID,
        manager_contract_configuration: [
          { key: 'IPINFO_TOKEN', value: ['updated-token-456'] },
          { key: 'CONNECTOR_AUTO', value: ['false'] },
          { key: 'CONNECTOR_LOG_LEVEL', value: ['debug'] },
          ...ipinfoListProperties
        ]
      };

      const result = await queryAsAdminWithSuccess({
        query: EDIT_MANAGED_CONNECTOR_MUTATION,
        variables: { input }
      });

      expect(result.data).toBeDefined();
      expect(result.data?.managedConnectorEdit.name).toEqual('Updated IpInfo Connector');
      expect(result.data?.managedConnectorEdit.manager_contract_configuration).toBeDefined();
      const autoConfig = result.data?.managedConnectorEdit.manager_contract_configuration
        .find((c: any) => c.key === 'CONNECTOR_AUTO');
      expect(autoConfig.value).toEqual('false');
    });
  });

  describe('Permission checks', () => {
    it('should deny non-admin users from registering connector composer', async () => {
      const input = {
        id: uuidv4(),
        name: 'Unauthorized Composer'
      };

      await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
        query: REGISTER_CONNECTORS_MANAGER_MUTATION,
        variables: { input }
      });
    });

    it('should deny non-admin users from adding managed connector', async () => {
      const input = {
        name: 'Unauthorized Connector',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: 'test-catalog',
        manager_contract_image: 'test-image',
        manager_contract_configuration: []
      };

      await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
        query: ADD_MANAGED_CONNECTOR_MUTATION,
        variables: { input }
      });
    });

    it('should allow connector user to update connector logs via XTM Composer', async () => {
      // Get test connector from catalog
      const testConnector = catalogHelper.getTestSafeConnector();
      const catalogId = catalogHelper.getCatalogId();

      // Create a connector for this test
      const createInput = {
        name: 'Permission Test Connector',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: catalogId,
        manager_contract_image: testConnector.container_image,
        manager_contract_configuration: catalogHelper.getMinimalConfig(testConnector, {
          IPINFO_TOKEN: 'permission-test-token',
          ...ipinfoProperties
        })
      };

      const createResult = await queryAsAdminWithSuccess({
        query: ADD_MANAGED_CONNECTOR_MUTATION,
        variables: { input: createInput }
      });

      const testConnectorId = createResult.data?.managedConnectorAdd.id;
      // Note: Not adding to createdConnectorIds as it's cleaned up in this test

      // Test that connector user can update logs
      const input = {
        id: testConnectorId,
        logs: ['User log line from connector']
      };

      const result = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
        query: UPDATE_CONNECTOR_LOGS_MUTATION,
        variables: { input }
      });

      expect(result.data.updateConnectorLogs).toBeDefined();

      // Cleanup
      await queryAsAdminWithSuccess({
        query: DELETE_CONNECTOR_MUTATION,
        variables: { id: testConnectorId }
      });
    });

    it('should deny non-admin users from deleting a connector', async () => {
      // Get test connector from catalog
      const testConnector = catalogHelper.getTestSafeConnector();
      const catalogId = catalogHelper.getCatalogId();

      // First create a connector as admin
      const input = {
        name: 'Connector for Permission Test',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: catalogId,
        manager_contract_image: testConnector.container_image,
        manager_contract_configuration: catalogHelper.getMinimalConfig(testConnector, {
          IPINFO_TOKEN: 'permission-test-token',
          ...ipinfoProperties
        })
      };

      const createResult = await queryAsAdminWithSuccess({
        query: ADD_MANAGED_CONNECTOR_MUTATION,
        variables: { input }
      });

      expect(createResult.data).toBeDefined();
      const testConnectorId = createResult.data?.managedConnectorAdd.id;
      // Note: Not adding to createdConnectorIds as it's cleaned up in this test

      // Try to delete as non-admin user
      await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
        query: DELETE_CONNECTOR_MUTATION,
        variables: { id: testConnectorId }
      });

      // Cleanup - delete as admin
      await queryAsAdminWithSuccess({
        query: DELETE_CONNECTOR_MUTATION,
        variables: { id: testConnectorId }
      });
    });
  });

  describe('Complete lifecycle test', () => {
    it('should handle complete lifecycle of a managed connector', async () => {
      // Get test connector from catalog
      const testConnector = catalogHelper.getTestSafeConnector();
      const catalogId = catalogHelper.getCatalogId();

      // Create
      const createInput = {
        name: 'Lifecycle Test Connector',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: catalogId,
        manager_contract_image: testConnector.container_image,
        manager_contract_configuration: catalogHelper.getMinimalConfig(testConnector, {
          IPINFO_TOKEN: 'lifecycle-test-token',
          ...ipinfoProperties
        })
      };

      const createResult = await queryAsAdminWithSuccess({
        query: ADD_MANAGED_CONNECTOR_MUTATION,
        variables: { input: createInput }
      });

      expect(createResult.data).toBeDefined();
      const lifecycleConnectorId = createResult.data?.managedConnectorAdd.id;

      // Deploy (start)
      await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
        variables: { input: { id: lifecycleConnectorId, status: 'starting' } }
      });

      // XTM Composer deploys
      await xtmComposer.deployConnector(lifecycleConnectorId);

      // Update logs during operation
      await xtmComposer.updateConnectorLogs(lifecycleConnectorId, [
        'Lifecycle test: processing IP data',
        'Lifecycle test: enriched 50 observables'
      ]);

      // Stop
      await queryAsAdminWithSuccess({
        query: UPDATE_CONNECTOR_REQUESTED_STATUS_MUTATION,
        variables: { input: { id: lifecycleConnectorId, status: 'stopping' } }
      });

      // XTM Composer stops
      await xtmComposer.stopConnector(lifecycleConnectorId);

      // Delete
      const deleteResult = await queryAsAdminWithSuccess({
        query: DELETE_CONNECTOR_MUTATION,
        variables: { id: lifecycleConnectorId }
      });

      expect(deleteResult.data).toBeDefined();
      expect(deleteResult.data?.deleteConnector).toEqual(lifecycleConnectorId);
    });
  });

  describe('Error handling', () => {
    it('should handle XTM Composer errors gracefully', async () => {
      // Get test connector from catalog
      const testConnector = catalogHelper.getTestSafeConnector();
      const catalogId = catalogHelper.getCatalogId();

      // Create a connector
      const createInput = {
        name: 'Error Test Connector',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: catalogId,
        manager_contract_image: testConnector.container_image,
        manager_contract_configuration: catalogHelper.getMinimalConfig(testConnector, {
          IPINFO_TOKEN: 'error-test-token',
          ...ipinfoProperties
        })
      };

      const createResult = await queryAsAdminWithSuccess({
        query: ADD_MANAGED_CONNECTOR_MUTATION,
        variables: { input: createInput }
      });

      const errorConnectorId = createResult.data?.managedConnectorAdd.id;

      // Don't request starting status, so deployment should fail
      try {
        await xtmComposer.deployConnector(errorConnectorId);
        expect.fail('Should have thrown an error');
      } catch (error: any) {
        expect(error.message).toContain('Connector not found or not in starting state');
      }

      // Cleanup
      await queryAsAdminWithSuccess({
        query: DELETE_CONNECTOR_MUTATION,
        variables: { id: errorConnectorId }
      });
    });

    it('should handle missing required configuration', async () => {
      // Get test connector from catalog
      const testConnector = catalogHelper.getTestSafeConnector();
      const catalogId = catalogHelper.getCatalogId();

      const input = {
        name: 'Missing Config Connector',
        user_id: TEST_USER_CONNECTOR_ID,
        catalog_id: catalogId,
        manager_contract_image: testConnector.container_image,
        manager_contract_configuration: [
          // Missing required fields - only providing one optional field
          { key: 'CONNECTOR_SCOPE', value: ['IPv4-Addr'] }
        ]
      };

      try {
        await queryAsAdminWithSuccess({
          query: ADD_MANAGED_CONNECTOR_MUTATION,
          variables: { input }
        });
        expect.fail('Should have thrown an error for missing required field');
      } catch (error) {
        expect(error).toBeDefined();
      }
    });
  });

  afterAll(async () => {
    // Stop the orchestration loop
    if (xtmComposer) {
      xtmComposer.stopOrchestration();
    }

    // Final cleanup of any remaining connectors
    const allConnectorsToDelete = Array.from(createdConnectorIds).filter(Boolean);

    await Promise.all(
      allConnectorsToDelete.map(async (connectorId) => {
        try {
          await queryAsAdminWithSuccess({
            query: DELETE_CONNECTOR_MUTATION,
            variables: { id: connectorId }
          });
        } catch (error: any) {
          // Ignore if already deleted
          const isAlreadyDeleted = error?.data?.errors?.some((e: any) => e.extensions?.code === 'ALREADY_DELETED_ERROR');

          if (!isAlreadyDeleted) {
            console.warn(`Cleanup: Failed to delete connector ${connectorId}`, error);
          }
        }
      })
    );
  });
});
