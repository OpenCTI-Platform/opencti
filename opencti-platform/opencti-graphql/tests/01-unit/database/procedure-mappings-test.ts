import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { checkStixCoreRelationshipMapping } from '../../../src/database/stix';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';

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
    ['Process', 'Procedure', 'component-of'],
    ['StixFile', 'Procedure', 'component-of'],
    ['Text', 'Procedure', 'component-of'],
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

  it('rejects component-of from Malware', () => {
    expect(checkStixCoreRelationshipMapping('Malware', 'Procedure', 'component-of')).toBe(false);
  });

  it('registers the component index and type on component-of only', () => {
    expect(schemaAttributesDefinition.getAttribute('component-of', 'component_index')).toBeDefined();
    expect(schemaAttributesDefinition.getAttribute('component-of', 'component_type')).toBeDefined();
    expect(schemaAttributesDefinition.getAttribute('uses', 'component_index')).toBeUndefined();
    expect(schemaAttributesDefinition.getAttribute('uses', 'component_type')).toBeUndefined();
  });
});
