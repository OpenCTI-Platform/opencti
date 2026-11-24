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
  it('gives a type without its own rules the shared ones, containers included', () => {
    expect(rulesForType('threat_custom', ['Report']).map((r) => r.key)).toEqual(['one-of', 'has-label', 'mentions', 'in-container']);
    expect(rulesForType('threat_custom', ['IPv4-Addr', 'Sector']).map((r) => r.key)).toEqual(['one-of', 'has-label', 'mentions', 'in-container']);
  });
  it('keeps advanced search criteria out of the rule lists: menus offer them on their own', () => {
    expect(rulesForType('threat_custom', ['Malware']).map((r) => r.key)).not.toContain('advanced');
    expect(rulesForGroup('malware', ['Malware']).map((r) => r.key)).not.toContain('advanced');
  });
  it('offers no rule while nothing is flagged', () => {
    expect(rulesForType('threat_custom', [])).toEqual([]);
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
