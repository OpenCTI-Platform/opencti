import { afterAll, beforeAll, describe, it } from 'vitest';
import { v4 as uuid } from 'uuid';
import { connectorDelete, registerConnector, updateConnectorWithConnectorInfo } from '../../../src/domain/connector';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { RegisterConnectorInput } from '../../../src/generated/graphql';
import { ConnectorType } from '../../../src/generated/graphql';
import type { ConnectorInfo } from '../../../src/types/connector';
import type { BasicStoreEntityConnector } from '../../../src/connector/connector';

describe('pingConnector behavior validation', () => {
  let connector: BasicStoreEntityConnector;
  beforeAll(async () => {
    const registerInput: RegisterConnectorInput = {
      type: ConnectorType.ExternalImport,
      id: uuid(),
      name: 'fake-connector'
    };
    connector = await registerConnector(testContext, ADMIN_USER, registerInput);

    // Set connector to active for tests purpose
    // await patchAttribute(testContext, ADMIN_USER, connector.id, ENTITY_TYPE_CONNECTOR, { active: true });
  });

  it('should connector run and terminate and buffering be stored', async () => {
    const connectorInfo: ConnectorInfo = {
      buffering: true,
      queue_messages_size: 0,
      queue_threshold: 0,
      run_and_terminate: true,
      next_run_datetime: 'NA'
    };
    const pingUpdateResult = await updateConnectorWithConnectorInfo(testContext, ADMIN_USER, connector, 'Active', connectorInfo);
    console.log('pingResult:', pingUpdateResult);
  });

  it('should connector run and terminate and running be stored', async () => {
    console.log('connector:', connector);
    // pingConnector(testContext, USER_CONNECTOR,);
  });

  it('should connector cron-like and buffering be stored', async () => {
    console.log('connector:', connector);
    // pingConnector(testContext, USER_CONNECTOR,);
  });

  afterAll(async () => {
    // const deletedConnector = await connectorDelete(testContext, ADMIN_USER, connector.id);
    // console.log('deletedConnector:', deletedConnector);
  });
});
