import { describe, expect, it } from 'vitest';
import { transformHasCoveredFromId } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-utils';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { testContext } from '../../../utils/testQuery';

describe('Function transformHasCoveredFromId', () => {
  it('should replace security coverage id by security coverage result id', async () => {
    const newInput = await transformHasCoveredFromId(
      testContext,
      SYSTEM_USER,
      {
        relationship_type: 'has-covered',
        external_uri: 'http://192.168.1.150:8080/admin/scenarios/001d6ae0-4344-4467-99d5-eb4b6962fd4b',
        fromId: 'security-coverage--c76bfcfe-2be5-500f-9b81-367457f1088f',
        toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
      },
    );
    expect(newInput).toEqual({
      relationship_type: 'has-covered',
      external_uri: 'http://192.168.1.150:8080/admin/scenarios/001d6ae0-4344-4467-99d5-eb4b6962fd4b',
      fromId: 'security-coverage-result--02464c1b-a817-5411-bbcf-4728d1675d15',
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
});
