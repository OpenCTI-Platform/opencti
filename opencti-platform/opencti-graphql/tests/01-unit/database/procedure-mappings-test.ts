import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { checkStixCoreRelationshipMapping } from '../../../src/database/stix';

describe('Procedure relationship mappings', () => {
  it.each([
    ['Procedure', 'Attack-Pattern', 'implements-technique'],
    ['Procedure', 'Tool', 'uses'],
    ['Procedure', 'Malware', 'uses'],
    ['Procedure', 'Vulnerability', 'exploits'],
    ['Intrusion-Set', 'Procedure', 'uses'],
    ['Threat-Actor-Group', 'Procedure', 'uses'],
    ['Threat-Actor-Individual', 'Procedure', 'uses'],
    ['Campaign', 'Procedure', 'uses'],
    ['Indicator', 'Procedure', 'indicates'],
    ['Course-Of-Action', 'Procedure', 'mitigates'],
  ])('allows %s %s %s', (from, to, type) => {
    expect(checkStixCoreRelationshipMapping(from, to, type)).toBe(true);
  });

  it('rejects implements-technique from Malware', () => {
    expect(checkStixCoreRelationshipMapping('Malware', 'Attack-Pattern', 'implements-technique')).toBe(false);
  });
});
