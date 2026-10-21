import { describe, expect, it } from 'vitest';
import { buildNamedItems } from '../../../../src/modules/timeMachine/landscapeDiff-domain';
import type { BasicStoreObject } from '../../../../src/types/store';

const target = (type: string, entityIds: string[]) => ({ type, relationshipTypes: new Set(['uses']), entityIds: new Set(entityIds) });

describe('Landscape diff named items', () => {
  const acc = {
    targets: new Map([
      ['technique-1', target('Attack-Pattern', ['intrusion-set-1', 'intrusion-set-2'])],
      ['malware-1', target('Malware', ['intrusion-set-1'])],
      ['restricted-1', target('Malware', ['intrusion-set-1'])],
    ]),
  };
  const resolved = {
    'technique-1': { entity_type: 'Attack-Pattern', standard_id: 'attack-pattern--a1', name: 'Phishing', x_mitre_id: 'T1566' },
    'malware-1': { entity_type: 'Malware', standard_id: 'malware--m1', name: 'Emotet', x_mitre_id: 'S0367' },
  } as unknown as Record<string, BasicStoreObject>;

  it('should give the STIX id of each item and the ATT&CK id of techniques only', () => {
    const items = buildNamedItems(acc, resolved, () => true);
    expect(items).toEqual([
      { id: 'technique-1', standard_id: 'attack-pattern--a1', entity_type: 'Attack-Pattern', name: '[T1566] Phishing', x_mitre_id: 'T1566', count: 2 },
      { id: 'malware-1', standard_id: 'malware--m1', entity_type: 'Malware', name: '[S0367] Emotet', x_mitre_id: null, count: 1 },
    ]);
  });

  it('should leave out the items the user cannot access and the ones the predicate rejects', () => {
    const items = buildNamedItems(acc, resolved, (t) => t.type === 'Malware');
    expect(items.map((item) => item.id)).toEqual(['malware-1']);
  });
});
