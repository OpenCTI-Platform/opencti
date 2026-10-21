import { describe, expect, it } from 'vitest';
import { buildUnresolvedMappedEntities } from '../../../src/domain/stixCoreObject';

describe('buildUnresolvedMappedEntities', () => {
  const IPV4_ID = 'ipv4-addr--0b7ba9cc-7c6b-5ac6-9d1a-35d6a5e1fb2f';
  const MALWARE_ID = 'malware--4a2d1f6e-7d35-5ab1-9d41-2c7c4f0f9b1a';
  const FILE_ID = 'file--8f1c0c35-3a0e-5d25-9e0f-1d7f6f0b3a11';

  it('should keep the suggestions that match no existing object, with the type of their STIX id', () => {
    const analysis = { '203.0.113.7': IPV4_ID, DeedRAT: MALWARE_ID, 'payload.zip': FILE_ID };
    const resolved = { [MALWARE_ID]: { id: 'malware-internal-id' } };
    expect(buildUnresolvedMappedEntities(analysis, resolved)).toEqual([
      { matchedString: '203.0.113.7', standardId: IPV4_ID, entityType: 'IPv4-Addr' },
      { matchedString: 'payload.zip', standardId: FILE_ID, entityType: 'StixFile' },
    ]);
  });

  it('should ignore empty values and values that are not STIX ids', () => {
    const analysis = { empty: '', internal: '6a1b8c1e-0b0c-4b8e-9e6d-0b6d6b0a8f5e', missing: null };
    expect(buildUnresolvedMappedEntities(analysis, {})).toEqual([]);
  });
});
