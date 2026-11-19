import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { checkStixCoreRelationshipMapping } from '../../../src/database/stix';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';

describe('Procedure relationship mappings', () => {
  it.each([
    ['Procedure', 'Attack-Pattern', 'implements-technique'],
    ['Procedure', 'Tool', 'uses'],
    ['Procedure', 'Malware', 'uses'],
    ['Procedure', 'Vulnerability', 'exploits'],
    ['Procedure', 'Process', 'has-observable'],
    ['Procedure', 'StixFile', 'has-observable'],
    ['Procedure', 'IPv4-Addr', 'has-observable'],
    ['Intrusion-Set', 'Procedure', 'uses'],
    ['Threat-Actor-Group', 'Procedure', 'uses'],
    ['Threat-Actor-Individual', 'Procedure', 'uses'],
    ['Campaign', 'Procedure', 'uses'],
    ['Indicator', 'Procedure', 'indicates'],
    ['Course-Of-Action', 'Procedure', 'mitigates'],
    ['Security-Coverage-Result', 'Procedure', 'has-covered'],
    ['SecurityPlatform', 'Procedure', 'should-cover'],
    ['Organization', 'Procedure', 'should-cover'],
  ])('allows %s %s %s', (from, to, type) => {
    expect(checkStixCoreRelationshipMapping(from, to, type)).toBe(true);
  });

  it('rejects implements-technique from Malware', () => {
    expect(checkStixCoreRelationshipMapping('Malware', 'Attack-Pattern', 'implements-technique')).toBe(false);
  });

  it('rejects has-observable from Malware', () => {
    expect(checkStixCoreRelationshipMapping('Malware', 'StixFile', 'has-observable')).toBe(false);
  });

  it('no longer stores procedure observables as a ref', () => {
    expect(schemaRelationsRefDefinition.getRelationRef('Procedure', 'procedureObservables')).toBeNull();
  });
});
