import { describe, expect, it } from 'vitest';
import { IR_PIR_TYPES, rulesForGroup, rulesForType } from './irPresetRules';

describe('rulesForType', () => {
  it('lists the malware rules plus the shared ones', () => {
    expect(rulesForType('malware', ['Malware']).map((r) => r.key)).toEqual(expect.arrayContaining(
      ['one-of', 'has-label', 'mentions', 'in-container', 'targets', 'uses', 'indicated', 'malware-type', 'communicates', 'variant-of', 'exploits', 'authored-by', 'capability'],
    ));
    expect(rulesForType('malware', ['Malware']).map((r) => r.key)).not.toContain('kev');
  });
  it('gives threat custom every rule that applies to the chosen flags', () => {
    const keys = rulesForType('threat_custom', ['Malware', 'Vulnerability']).map((r) => r.key);
    expect(keys).toEqual(expect.arrayContaining(['malware-type', 'kev', 'affects']));
    expect(keys).not.toContain('impersonates');
  });
  it('lists nothing for fraud', () => {
    expect(IR_PIR_TYPES.find((t) => t.key === 'fraud')?.enabled).toBe(false);
  });
});

describe('rulesForGroup', () => {
  it('never offers a keywords rule inside a group', () => {
    expect(rulesForGroup('malware', ['Malware']).map((r) => r.key)).not.toContain('mentions');
  });
});
