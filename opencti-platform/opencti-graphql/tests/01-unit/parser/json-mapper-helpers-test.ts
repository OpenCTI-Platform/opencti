import { describe, expect, it, vi } from 'vitest';
import { decisionMatrix, extractWithRegexp, withJsonMapperHelpers } from '../../../src/parser/json-mapper-helpers';

describe('JSON mapper formula helpers', () => {
  it('should extract a regexp group, or keep the value without a match', () => {
    expect(extractWithRegexp('(.*)( - )([A-Z][0-9]{1,})', 1, 'APT - G0007')).toEqual('APT');
    expect(extractWithRegexp('(.*)( - )([A-Z][0-9]{1,})', 3, 'APT - G0007')).toEqual('G0007');
    expect(extractWithRegexp('^(\\d+)$', 1, 'no digits')).toEqual('no digits');
  });

  it('should pick the result of the matching row, or the default', () => {
    const matrix = [{ value: 'high', result: 90 }, { value: 'low', result: 10 }];
    expect(decisionMatrix('low', 50, matrix)).toEqual(10);
    expect(decisionMatrix('medium', 50, matrix)).toEqual(50);
  });

  it('should add the helpers to the data and send patternFromValue to the host call', () => {
    const hostCall = vi.fn(() => '[ipv4-addr:value = \'1.2.3.4\']');
    const data = withJsonMapperHelpers({ ip: '1.2.3.4' }, hostCall);
    expect(data.ip).toEqual('1.2.3.4');
    expect(data.extractWithRegexp).toBe(extractWithRegexp);
    expect(data.decisionMatrix).toBe(decisionMatrix);
    expect(data.patternFromValue('IPv4-Addr', ['1.2.3.4'])).toEqual('[ipv4-addr:value = \'1.2.3.4\']');
    expect(hostCall).toHaveBeenCalledWith('patternFromValue', ['IPv4-Addr', ['1.2.3.4']]);
  });

  it('should fail patternFromValue when host calls are not available', () => {
    expect(() => withJsonMapperHelpers({}).patternFromValue('IPv4-Addr', '1.2.3.4')).toThrow('Host calls are not available');
  });
});
