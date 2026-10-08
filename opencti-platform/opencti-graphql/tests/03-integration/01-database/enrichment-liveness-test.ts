import { afterAll, beforeAll, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import * as rabbitmq from '../../../src/database/rabbitmq';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR } from '../../utils/testQuery';
import { addSecurityCoverage, securityCoverageDelete } from '../../../src/modules/securityCoverage/securityCoverage-domain';
import { addIntrusionSet } from '../../../src/domain/intrusionSet';
import { connectorDelete, pingConnector, registerConnector } from '../../../src/domain/connector';
import { getEntitiesListFromCache, resetCacheForEntity } from '../../../src/database/cache';
import { deleteElementById } from '../../../src/database/middleware';
import { redisDeleteConnectorHeartbeat } from '../../../src/database/redis';
import { resolveUserByIdFromCache } from '../../../src/modules/user/user-domain';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CONNECTOR } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../../../src/modules/securityCoverage/securityCoverage-types';
import { ConnectorType } from '../../../src/generated/graphql';
import type { AuthUser } from '../../../src/types/user';
import type { BasicStoreEntityConnector } from '../../../src/types/connector';

// ---------------------------------------------------------------------------
// Regression tests for OpenCTI-Platform/opencti#18853: the connectors cache is
// only reloaded on connectors events, while liveness changes with the pings
// (or their absence). Automatic enrichment must rely on the current liveness,
// not on the `active` snapshot taken when the cache was loaded.
// ---------------------------------------------------------------------------

const CONNECTOR_ID = '33333333-3333-3333-3333-333333333333';

describe('Automatic enrichment and connectors liveness', () => {
  let connectorUser: AuthUser;
  let covered: { id: string; internal_id: string; standard_id: string };
  let coverageId: string;
  let pushToConnector: MockInstance;

  const enrichments = () => pushToConnector.mock.calls.filter((call) => call[0] === CONNECTOR_ID).length;
  const loadConnectorsCache = async () => {
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const cached = await getEntitiesListFromCache<BasicStoreEntityConnector>(testContext, ADMIN_USER, ENTITY_TYPE_CONNECTOR);
    return cached.find((c) => c.id === CONNECTOR_ID);
  };

  beforeAll(async () => {
    connectorUser = await resolveUserByIdFromCache(testContext, await getUserIdByEmail(USER_CONNECTOR.email)) as AuthUser;
    await registerConnector(testContext, ADMIN_USER, {
      id: CONNECTOR_ID,
      name: 'Liveness enrichment connector',
      type: ConnectorType.InternalEnrichment,
      scope: [ENTITY_TYPE_SECURITY_COVERAGE],
      auto: true,
      auto_update: true,
    }, { connector_user_id: connectorUser.id });
  });

  afterAll(async () => {
    await connectorDelete(testContext, ADMIN_USER, CONNECTOR_ID);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  });

  beforeEach(async () => {
    covered = await addIntrusionSet(testContext, ADMIN_USER, { name: `Intrusion-Set ${Date.now()}` });
    pushToConnector = vi.spyOn(rabbitmq, 'pushToConnector').mockResolvedValue(undefined as never);
    return async () => {
      vi.restoreAllMocks();
      await securityCoverageDelete(testContext, ADMIN_USER, coverageId);
      await deleteElementById(testContext, ADMIN_USER, covered.id, ENTITY_TYPE_INTRUSION_SET);
    };
  });

  it('should not enrich with a connector that died after the connectors cache was loaded', async () => {
    await pingConnector(testContext, ADMIN_USER, CONNECTOR_ID, '{}', undefined as never);
    expect((await loadConnectorsCache())?.active).toBe(true);
    // The connector stops pinging: no connector event, the cache is not reloaded
    await redisDeleteConnectorHeartbeat(CONNECTOR_ID);

    ({ id: coverageId } = await addSecurityCoverage(testContext, ADMIN_USER, { name: 'coverage', objectCovered: covered.standard_id, auto_enrichment_disable: false }));

    expect(enrichments()).toEqual(0);
  });

  it('should enrich with a connector that came back after the connectors cache was loaded', async () => {
    await redisDeleteConnectorHeartbeat(CONNECTOR_ID);
    expect((await loadConnectorsCache())?.active).toBe(false);
    // The connector pings again without registering: no connector event, the cache is not reloaded
    await pingConnector(testContext, ADMIN_USER, CONNECTOR_ID, '{}', undefined as never);

    ({ id: coverageId } = await addSecurityCoverage(testContext, ADMIN_USER, { name: 'coverage', objectCovered: covered.standard_id, auto_enrichment_disable: false }));

    expect(enrichments()).toEqual(1);
  });
});
