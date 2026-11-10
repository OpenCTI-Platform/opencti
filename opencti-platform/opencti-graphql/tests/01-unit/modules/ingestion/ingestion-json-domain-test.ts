import { describe, expect, it } from 'vitest';
import { mergeIngestionJsonState, sanitizeExportedQueryAttributes } from '../../../../src/modules/ingestion/ingestion-json-domain';
import type { DataParam } from '../../../../src/modules/ingestion/ingestion-types';

const attribute = (to: string, state_operation: DataParam['state_operation']) => ({
  type: 'data', from: `meta.${to}`, to, default: '', state_operation, data_operation: 'data', exposed: 'query_param',
} as DataParam);

describe('ingestion-json-domain: mergeIngestionJsonState', () => {
  it('should add the new value to the previous one for a sum attribute', () => {
    expect(mergeIngestionJsonState([attribute('offset', 'sum')], { offset: 10 }, { offset: 5 })).toEqual({ offset: 15 });
  });

  it('should count a missing side as 0 for a sum attribute, and parse numeric strings', () => {
    expect(mergeIngestionJsonState([attribute('offset', 'sum')], {}, { offset: '5' })).toEqual({ offset: 5 });
    expect(mergeIngestionJsonState([attribute('offset', 'sum')], { offset: '10' }, {})).toEqual({ offset: 10 });
  });

  it('should take the new value for a replace attribute', () => {
    expect(mergeIngestionJsonState([attribute('cursor', 'replace')], { cursor: 'a' }, { cursor: 'b' })).toEqual({ cursor: 'b' });
  });

  it('should keep the previous value for a replace attribute when the new one is empty', () => {
    expect(mergeIngestionJsonState([attribute('cursor', 'replace')], { cursor: 'a' }, { cursor: '' })).toEqual({ cursor: 'a' });
    expect(mergeIngestionJsonState([attribute('cursor', 'replace')], { cursor: 'a' }, {})).toEqual({ cursor: 'a' });
  });

  it('should only keep the declared attributes', () => {
    const state = mergeIngestionJsonState([attribute('offset', 'sum'), attribute('cursor', 'replace')], { offset: 1, other: 'x' }, { offset: 2, cursor: 'c', extra: 'y' });
    expect(state).toEqual({ offset: 3, cursor: 'c' });
  });

  it('should return an empty state without query attributes', () => {
    expect(mergeIngestionJsonState(undefined, { offset: 1 }, { offset: 2 })).toEqual({});
  });
});

describe('ingestion-json-domain: sanitizeExportedQueryAttributes', () => {
  it('blanks the default of a query attribute sent in a sensitive header only', () => {
    const attributes = [
      { type: 'header', from: 'x-next', to: 'X-Api-Key', default: 'secret-key', exposed: 'header' },
      { type: 'data', from: 'cursor', to: 'cursor', default: '0', exposed: 'query_param' },
      { type: 'header', from: 'x-page', to: 'X-Page', default: '1', exposed: 'header' },
    ];
    expect(sanitizeExportedQueryAttributes(attributes)?.map(({ default: value }) => value)).toEqual(['', '0', '1']);
  });
});
