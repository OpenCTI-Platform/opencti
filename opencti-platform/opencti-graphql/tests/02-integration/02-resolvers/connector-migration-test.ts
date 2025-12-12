import gql from 'graphql-tag';

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { registerConnector } from '../../../src/domain/connector';
import { ConnectorType } from '../../../src/generated/graphql';
import * as catalogDomain from '../../../src/modules/catalog/catalog-domain';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { adminQueryWithSuccess, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

const CREATE_USER_QUERY = gql`
  mutation UserAdd($input: UserAddInput!) {
    userAdd(input: $input) {
      id
      standard_id
      name
      user_email
      firstname
      lastname
      user_service_account
    }
  }
`;

const DELETE_USER_MUTATION = gql`
  mutation DeleteUser($id: ID!) {
    userEdit(id: $id) {
      delete
    }
  }
`;

const MIGRATE_CONNECTOR_TO_MANAGED = gql`
  mutation MigrateConnectorToManaged($input: MigrateConnectorToManagedInput!) {
    connectorMigrateToManaged(input: $input){
      connector {
        id
        name
        standard_id
        manager_contract_configuration {
          key
          value
        }
        connector_user {
          user_service_account
        }
      }   
    }
}`;

const DELETE_CONNECTOR_QUERY = gql`
  mutation ConnectorDeletionMutation($id: ID!) {
    deleteConnector(id: $id)
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
      connector_user_id
      connector_user {
        user_service_account
      }
      connector_state
      connector_state_timestamp
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

const TEST_CN_ID = '5ed680de-75e2-4aa0-bec0-4e8e5a0d1695';
const TEST_CN_NAME = 'TestConnector';

describe('Check connector migration', () => {
  let userId: string;

  /**
   * - Create a user account without being a service account
   * - Register a standalone connector
   * - Get catalogId
   */
  beforeAll(async () => {
    const user = await adminQueryWithSuccess({
      query: CREATE_USER_QUERY,
      variables: { input: {
        name: 'firstname lastname',
        password: 'password',
        user_email: 'user@test.com',
        user_service_account: false,
        groups: [],
        objectOrganization: [],
      } },
    });

    userId = user.data.userAdd.id;

    const connectorData = {
      id: TEST_CN_ID,
      name: TEST_CN_NAME,
      type: ConnectorType.ExternalImport,
      scope: ['Observable'],
      auto: true,
      only_contextual: true,
    };

    const opts = {
      connector_user_id: userId,
    };

    // register connector with domain function because the graphql
    // RegisterConnectorInput doesn't accept options input which is required
    // to pass the userId to the connector
    const connector = await registerConnector(
      testContext,
      ADMIN_USER,
      connectorData,
      opts
    );

    expect(connector).not.toBeNull();
    expect(connector.name).toEqual(TEST_CN_NAME);
    expect(connector.id).toEqual(TEST_CN_ID);
  });

  /**
   * - delete the user created
   * - delete the connector
   */
  afterAll(async () => {
    // Delete the connector
    await queryAsAdminWithSuccess({ query: DELETE_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });

    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.connector).toBeNull();

    await queryAsAdminWithSuccess({ query: DELETE_USER_MUTATION, variables: { id: userId } });
  });

  describe('migrate connector to managed', () => {
    describe('when migration is successful', () => {
      it('shoud migrate a standalone connector to managed, and user is now service account', async () => {
        const queryConnectorRegistered = await queryAsAdmin({ query: READ_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
        const standaloneConnector = queryConnectorRegistered.data?.connector;
        expect(standaloneConnector).not.toBeNull();

        if (!standaloneConnector) {
          throw new Error('Connector should not be null');
        }

        expect(standaloneConnector.connector_state).toBeNull();
        expect(standaloneConnector.connector_state_timestamp).not.toBeNull();
        expect(standaloneConnector.connector_user_id).toMatch(userId);
        expect(standaloneConnector.connector_user.user_service_account).toBeFalsy();

        const managedConnectorResult = await adminQueryWithSuccess({
          query: MIGRATE_CONNECTOR_TO_MANAGED,
          variables: {
            input: {
              connectorId: standaloneConnector.id,
              containerImage: 'opencti/connector-cve',
              resetConnectorState: false,
              convertUserToServiceAccount: true,
              configuration: [
                { key: 'CVE_API_KEY', value: 'cve_api_key' },
                // all other keys are get from catalog contract
              ]
            }
          }
        });

        const contractFound = catalogDomain.findContractByContainerImage(testContext, ADMIN_USER, 'opencti/connector-cve');
        if (!contractFound?.contract) {
          throw new Error('Connector nist-nvd-cve container-image not found in catalog');
        }

        let contractParsed;
        try {
          contractParsed = JSON.parse(contractFound?.contract);
        } catch {
          throw new Error('Cannot parse nist-nvd-cve catalog');
        }

        if (!contractParsed) {
          throw new Error('Contract nist-nvd-cve catalog is undefined');
        }

        // same values excluded from catalog-domain
        const RUNTIME_KEYS = ['CONNECTOR_ID', 'CONNECTOR_TYPE', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'HTTPS_PROXY_REJECT_UNAUTHORIZED'];
        const managedConnector = managedConnectorResult.data.connectorMigrateToManaged.connector;
        const rawConfig = managedConnector.manager_contract_configuration;
        rawConfig.filter((c: any) => !RUNTIME_KEYS.includes(c.key));

        const actualConfig = rawConfig.filter((c: { key: string }) => !RUNTIME_KEYS.includes(c.key));
        const schemaProperties = contractParsed.config_schema.properties;

        const expectedKeys = Object.keys(schemaProperties).filter(
          (key) => !key.endsWith('API_KEY')
        );

        const actualKeys = actualConfig.map((c: { key: string }) => c.key);

        // Assert all expected keys are present and no extra keys
        expect(actualKeys.sort()).toEqual(expectedKeys.sort());
        // connector state timestamp should be the same
        expect(managedConnector.connector_state_timestamp).not.toBeNull();
        // connector managed id is the same as the standalone one
        expect(managedConnector.id).toMatch(standaloneConnector.id);
        // user should be a service account
        expect(managedConnector.connector_user.user_service_account).toBeTruthy();
      });
    });
  });

  // it('should fail because the connector registered is not found', async () => {
  //   await adminQueryWithError(
  //     {
  //       query: MIGRATE_CONNECTOR_TO_MANAGED,
  //       variables: {
  //         input: {
  //           connectorId: 'threatfox-id-1',
  //           contractSlug: 'threatfox',
  //           preserveState: true,
  //           convertUserToServiceAccount: true,
  //           configuration: [
  //             { key: 'CONNECTOR_LOG_LEVEL', value: 'debug' },
  //           ]
  //         }
  //       }
  //     },
  //     'Connector not found',
  //     FUNCTIONAL_ERROR,
  //   );
  // });

  // it('should fail because the connector registered is not found', async () => {
  //   await adminQueryWithError(
  //     {
  //       query: MIGRATE_CONNECTOR_TO_MANAGED,
  //       variables: {
  //         input: {
  //           connectorId: 'threatfox-id-1',
  //           contractSlug: 'threatfox',
  //           preserveState: true,
  //           convertUserToServiceAccount: true,
  //           configuration: [
  //             { key: 'CONNECTOR_LOG_LEVEL', value: 'debug' },
  //           ]
  //         }
  //       }
  //     },
  //     'Connector not found',
  //     FUNCTIONAL_ERROR,
  //   );
  // });

  // TODELETE
  // it('should migrate a connector to a managed connector', async () => {
  //   const a = false;
  //   expect(a).toBe(false);

  //   const queryConnectorRegistered = await queryAsAdmin({ query: READ_CONNECTOR_QUERY, variables: { id: TEST_CN_ID } });
  //   const standaloneConnector = queryConnectorRegistered.data?.connector;
  //   expect(standaloneConnector).not.toBeNull();

  //   if (!standaloneConnector) {
  //     throw new Error('Connector should not be null');
  //   }

  //   expect(standaloneConnector.connector_state).toBeNull();
  //   expect(standaloneConnector.connector_state_timestamp).not.toBeNull();
  //   expect(standaloneConnector.connector_user_id).toMatch(userId);

  //   // console.log('queryResult', queryResult.data);

  //   // MIGRATE_CONNECTOR_TO_MANAGED;

  //   const managedConnector = await adminQueryWithSuccess({
  //     query: MIGRATE_CONNECTOR_TO_MANAGED,
  //     variables: {
  //       input: {
  //         connectorId: 'threatfox-id-1',
  //         contractSlug: 'threatfox',
  //         preserveState: true,
  //         convertUserToServiceAccount: true,
  //         configuration: [
  //           { key: 'CONNECTOR_LOG_LEVEL', value: 'debug' },
  //         ]
  //       }
  //     }
  //   });

  //   console.log('managedConnector', managedConnector);
  // });
});
