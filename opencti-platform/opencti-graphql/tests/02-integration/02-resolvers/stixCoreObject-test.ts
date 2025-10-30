import { describe, it, expect } from 'vitest';
import { findUnknownStixCoreObjects } from '../../../src/domain/stixCoreObject';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

describe('StixCoreObject resolver standard behavior', () => {
  it('findUnknownStixCoreObjects: should return unknown entities', async () => {
    const md5Hash = '757a71f0fbd6b3d993be2a213338d1f2';
    const malwareName = 'Paradise Ransomware';
    const locationName = 'france';
    const organizationAlias = 'Computer Incident';
    // no values provided
    let unknownValues = await findUnknownStixCoreObjects(testContext, ADMIN_USER, { values: [] });
    expect(unknownValues.length).toEqual(0);
    // some values are representative or hashes of a sco, some are unknown
    unknownValues = await findUnknownStixCoreObjects(testContext, ADMIN_USER, { values: ['unknownValue', locationName, md5Hash] });
    expect(unknownValues.length).toEqual(1);
    expect(unknownValues[0]).toEqual('unknownValue');
    // some values are aliases
    unknownValues = await findUnknownStixCoreObjects(testContext, ADMIN_USER, { values: ['unknownValue', organizationAlias] });
    expect(unknownValues.length).toEqual(1);
    expect(unknownValues[0]).toEqual('unknownValue');
    // values returned in alphabetical order
    unknownValues = await findUnknownStixCoreObjects(testContext, ADMIN_USER, { values: [malwareName, 'aa', locationName, 'cc', 'bb'], orderBy: 'value', orderMode: 'asc' });
    expect(unknownValues.length).toEqual(3);
    expect(unknownValues).toEqual(['aa', 'bb', 'cc']);
  });
});
