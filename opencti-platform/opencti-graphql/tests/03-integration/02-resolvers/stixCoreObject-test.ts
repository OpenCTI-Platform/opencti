import { describe, it, expect } from 'vitest';
import { findUnknownStixCoreObjects, stixCoreObjectsDistributionByEntity } from '../../../src/domain/stixCoreObject';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

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
    // should be case insensitive
    unknownValues = await findUnknownStixCoreObjects(testContext, ADMIN_USER, { values: ['unknownValue', locationName.toUpperCase(), md5Hash] });
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

describe('stixCoreObjectsDistributionByEntity', () => {
  // Malware Paradise Ransomware (malware--faa5b705-cf44-4e50-8472-29e5fec43c3c)
  // has relationships with attack-patterns and intrusion-set in test data

  it('should return distribution of related entities by entity_type', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware).toBeDefined();
    const distribution = await stixCoreObjectsDistributionByEntity(testContext, ADMIN_USER, {
      objectId: malware!.internal_id,
      field: 'entity_type',
      operation: 'count',
    });
    expect(distribution).toBeDefined();
    expect(distribution.length).toBeGreaterThan(0);
    const aggregationMap = new Map(distribution.map((i: { label: string; value: number }) => [i.label, i.value]));
    // Malware Paradise Ransomware is related to Attack-Patterns and Intrusion-Set
    expect(aggregationMap.get('Attack-Pattern')).toEqual(2);
    expect(aggregationMap.get('Intrusion-Set')).toEqual(1);
  });

  it('should throw ResourceNotFoundError for unknown objectId', async () => {
    await expect(stixCoreObjectsDistributionByEntity(testContext, ADMIN_USER, {
      objectId: '00000000-0000-0000-0000-000000000000',
      field: 'entity_type',
      operation: 'count',
    })).rejects.toThrow('Specified ids not found or restricted');
  });

  it('should support array of objectIds', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware).toBeDefined();
    const distribution = await stixCoreObjectsDistributionByEntity(testContext, ADMIN_USER, {
      objectId: [malware!.internal_id],
      field: 'entity_type',
      operation: 'count',
    });
    expect(distribution).toBeDefined();
    expect(distribution.length).toEqual(6);
  });

  it('should support limit option', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware).toBeDefined();
    const distribution = await stixCoreObjectsDistributionByEntity(testContext, ADMIN_USER, {
      objectId: malware!.internal_id,
      field: 'entity_type',
      operation: 'count',
      limit: 1,
    });
    expect(distribution).toBeDefined();
    expect(distribution.length).toEqual(1);
  });
});
