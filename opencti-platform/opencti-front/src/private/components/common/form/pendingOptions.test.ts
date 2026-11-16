import { describe, expect, it } from 'vitest';
import { PENDING_ENTITY_PREFIX } from '../../../../utils/hooks/useDeferredCreation';
import { buildPendingOptions } from './pendingOptions';

describe('buildPendingOptions', () => {
  it('labels an SDO option with its name', () => {
    const [option] = buildPendingOptions([{ name: 'APT42', description: 'x' }], 'Intrusion-Set', 'search');
    expect(option.label).toBe('APT42');
    expect(option.type).toBe('Intrusion-Set');
    expect(option.isPendingCreation).toBe(true);
    expect(option.value.startsWith(PENDING_ENTITY_PREFIX)).toBe(true);
    expect(option.pendingInputData).toEqual({ entityType: 'Intrusion-Set', input: { name: 'APT42', description: 'x' } });
  });

  it('gives each option of a bulk SCO creation its own observable value', () => {
    const inputs = ['1.1.1.1', '2.2.2.2', '3.3.3.3'].map((value) => ({ type: 'IPv4-Addr', IPv4Addr: { value }, objectLabel: [] }));
    const options = buildPendingOptions(inputs, 'IPv4-Addr', '1.1.1.1\n2.2.2.2\n3.3.3.3');
    expect(options.map((o) => o.label)).toEqual(['1.1.1.1', '2.2.2.2', '3.3.3.3']);
    expect(new Set(options.map((o) => o.value)).size).toBe(3);
  });

  it('takes the type of the input when the dialog did not fix one', () => {
    const [option] = buildPendingOptions([{ type: 'Domain-Name', DomainName: { value: 'a.org' } }], null, '');
    expect(option.type).toBe('Domain-Name');
    expect(option.pendingInputData?.entityType).toBe('Domain-Name');
  });

  it('labels a file observable with its name or its hash', () => {
    const options = buildPendingOptions([
      { type: 'StixFile', StixFile: { name: 'evil.exe', hashes: [] } },
      { type: 'StixFile', StixFile: { hashes: [{ algorithm: 'MD5', hash: 'abc' }] } },
    ], 'StixFile', '');
    expect(options.map((o) => o.label)).toEqual(['evil.exe', 'abc']);
  });

  it('falls back to the search term when the input carries no label', () => {
    const [option] = buildPendingOptions([{ type: 'Text' }], 'Text', 'typed');
    expect(option.label).toBe('typed');
  });
});
