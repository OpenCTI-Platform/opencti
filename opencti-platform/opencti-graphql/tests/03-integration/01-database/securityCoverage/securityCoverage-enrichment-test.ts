import { afterAll, beforeAll, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import * as rabbitmq from '../../../../src/database/rabbitmq';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR } from '../../../utils/testQuery';
import { addSecurityCoverage, securityCoverageDelete } from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import { addAttackPattern } from '../../../../src/domain/attackPattern';
import { addIntrusionSet } from '../../../../src/domain/intrusionSet';
import { connectorDelete, registerConnector } from '../../../../src/domain/connector';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { deleteElementById } from '../../../../src/database/middleware';
import { resolveUserByIdFromCache } from '../../../../src/domain/user';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_INTRUSION_SET } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CONNECTOR } from '../../../../src/schema/internalObject';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import { ConnectorType } from '../../../../src/generated/graphql';
import type { AuthUser } from '../../../../src/types/user';

const CONNECTOR_A = '11111111-1111-1111-1111-111111111111';
const CONNECTOR_B = '22222222-2222-2222-2222-222222222222';

describe('SecurityCoverage enrichment', () => {
  let connectorUser: AuthUser;
  let attackPattern: { id: string };
  let covered: { id: string; internal_id: string; standard_id: string };
  let coverageId: string;
  let pushToConnector: MockInstance;

  const enrichmentsFor = (connectorId: string) => pushToConnector.mock.calls.filter((call) => call[0] === connectorId).length;

  const securityCoverageAdd = async (user: AuthUser, input = {}, context = testContext) => addSecurityCoverage(context, user, {
    name: 'coverage of the intrusion set',
    objectCovered: covered.standard_id,
    auto_enrichment_disable: false,
    ...input,
  });

  const workerContext = { ...testContext, workId: 'work_openaev' };
  const connectorResult = {
    external_uri: 'http://openaev.local/tenant-a',
    coverage_information: [{ coverage_name: 'detection', coverage_score: 50 }],
  };

  beforeAll(async () => {
    connectorUser = await resolveUserByIdFromCache(testContext, await getUserIdByEmail(USER_CONNECTOR.email)) as AuthUser;
    for (const [id, name] of [[CONNECTOR_A, 'OpenAEV coverage A'], [CONNECTOR_B, 'OpenAEV coverage B']]) {
      await registerConnector(testContext, ADMIN_USER, {
        id,
        name,
        type: ConnectorType.InternalEnrichment,
        scope: [ENTITY_TYPE_SECURITY_COVERAGE],
        auto: true,
        auto_update: true,
      }, { active: true, connector_user_id: connectorUser.id });
    }
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    attackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'T1000 coverage enrichment' });
  });

  afterAll(async () => {
    await connectorDelete(testContext, ADMIN_USER, CONNECTOR_A);
    await connectorDelete(testContext, ADMIN_USER, CONNECTOR_B);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    await deleteElementById(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
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

  it('should enrich each connector once when a user creates a coverage', async () => {
    ({ id: coverageId } = await securityCoverageAdd(ADMIN_USER));

    expect(enrichmentsFor(CONNECTOR_A)).toEqual(1);
    expect(enrichmentsFor(CONNECTOR_B)).toEqual(1);
  });

  it('should not enrich again when a connector writes its own result back', async () => {
    ({ id: coverageId } = await securityCoverageAdd(ADMIN_USER));
    pushToConnector.mockClear();

    await securityCoverageAdd(connectorUser, connectorResult, workerContext);

    expect(enrichmentsFor(CONNECTOR_A)).toEqual(0);
    expect(enrichmentsFor(CONNECTOR_B)).toEqual(0);
  });
});
