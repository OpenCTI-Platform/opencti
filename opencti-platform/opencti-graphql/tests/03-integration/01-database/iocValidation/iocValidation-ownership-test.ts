import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR, USER_EDITOR } from '../../../utils/testQuery';
import { connectorDelete, registerConnector } from '../../../../src/domain/connector';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { resolveUserByIdFromCache } from '../../../../src/modules/user/user-domain';
import { ENTITY_TYPE_CONNECTOR } from '../../../../src/schema/internalObject';
import { ConnectorType } from '../../../../src/generated/graphql';
import { assertRequestConnectorUser, findIocValidationConnectors } from '../../../../src/modules/iocValidation/iocValidation-domain';
import { IOC_VALIDATION_CONNECTOR_SCOPE, type BasicStoreEntityIocValidationRequest } from '../../../../src/modules/iocValidation/iocValidation-types';
import type { AuthUser } from '../../../../src/types/user';

const IOC_VALIDATION_CONNECTOR = '10101010-0a10-4a10-8a10-101010101010';

describe('IOC validation request ownership', () => {
  let connectorUser: AuthUser;
  let otherUser: AuthUser;
  const request = (connectorId?: string) => ({ internal_id: 'ioc-validation-request-test', connector_id: connectorId }) as BasicStoreEntityIocValidationRequest;

  beforeAll(async () => {
    connectorUser = await resolveUserByIdFromCache(testContext, await getUserIdByEmail(USER_CONNECTOR.email)) as AuthUser;
    otherUser = await resolveUserByIdFromCache(testContext, await getUserIdByEmail(USER_EDITOR.email)) as AuthUser;
    await registerConnector(testContext, ADMIN_USER, {
      id: IOC_VALIDATION_CONNECTOR,
      name: 'OpenAEV IOC validation',
      type: ConnectorType.InternalEnrichment,
      scope: [IOC_VALIDATION_CONNECTOR_SCOPE],
      auto: false,
      auto_update: false,
    }, { active: true, connector_user_id: connectorUser.id });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  });

  afterAll(async () => {
    await connectorDelete(testContext, ADMIN_USER, IOC_VALIDATION_CONNECTOR);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  });

  it('should list the connectors scoped to IOC validation requests', async () => {
    const connectors = await findIocValidationConnectors(testContext, ADMIN_USER);
    expect(connectors.map((connector: { internal_id: string }) => connector.internal_id)).toContain(IOC_VALIDATION_CONNECTOR);
  });

  it('should let the service account of the request connector report its status', async () => {
    await expect(assertRequestConnectorUser(testContext, connectorUser, request(IOC_VALIDATION_CONNECTOR))).resolves.toBeUndefined();
  });

  it('should let a bypass user report the status of any request', async () => {
    await expect(assertRequestConnectorUser(testContext, ADMIN_USER, request(IOC_VALIDATION_CONNECTOR))).resolves.toBeUndefined();
  });

  it('should refuse any other account', async () => {
    await expect(assertRequestConnectorUser(testContext, otherUser, request(IOC_VALIDATION_CONNECTOR))).rejects.toThrow();
    await expect(assertRequestConnectorUser(testContext, connectorUser, request(undefined))).rejects.toThrow();
  });
});
