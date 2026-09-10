import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { transformHasCoveredFromId } from '../../../../src/modules/securityCoverage/securityCoverage-utils';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { addSecurityCoverage, listSecurityCoverageResults, securityCoverageDelete } from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import type { BasicStoreEntitySecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import type { BasicStoreEntitySecurityCoverageResult } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';

describe('Function transformHasCoveredFromId', () => {
  let securityCoverage: BasicStoreEntitySecurityCoverage;
  let result: BasicStoreEntitySecurityCoverageResult;

  beforeEach(async () => {
    securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
      name: 'sc1',
      objectCovered: 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7',
      auto_enrichment_disable: true,
      external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a999',
    });
    result = (await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage))[0];
  });

  afterEach(async () => {
    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
  });

  it('should replace security coverage id by security coverage result id when valid external_uri', async () => {
    const newInput = await transformHasCoveredFromId(
      testContext,
      SYSTEM_USER,
      {
        relationship_type: 'has-covered',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a999',
        fromId: securityCoverage.standard_id,
        toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
      },
    );
    expect(newInput).toEqual({
      relationship_type: 'has-covered',
      external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a999',
      fromId: result.standard_id,
      toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
    });
  });

  it('should throw an error if invalid external uri', async () => {
    const call = () => transformHasCoveredFromId(
      testContext,
      SYSTEM_USER,
      {
        relationship_type: 'has-covered',
        external_uri: 'http://192.168.1.150:8080/admin/scenarios/hello-there',
        fromId: 'security-coverage--c76bfcfe-2be5-500f-9b81-367457f1088f',
        toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
      },
    );
    await expect(call()).rejects.toThrow('Cannot find SecurityCoverageResult for this has-covered relationship');
  });

  it('should replace security coverage id by security coverage result id when no external_uri', async () => {
    const newInput = await transformHasCoveredFromId(
      testContext,
      SYSTEM_USER,
      {
        relationship_type: 'has-covered',
        fromId: securityCoverage.standard_id,
        toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
      },
    );
    expect(newInput).toEqual({
      relationship_type: 'has-covered',
      fromId: result.standard_id,
      toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
    });
  });
});
