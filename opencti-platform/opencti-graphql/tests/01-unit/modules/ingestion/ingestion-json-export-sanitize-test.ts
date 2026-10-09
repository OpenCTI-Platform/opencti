import { describe, expect, it } from 'vitest';
import { sanitizeExportedHeaders, sanitizeExportedQueryAttributes } from '../../../../src/modules/ingestion/ingestion-json-domain';
import type { DataParam } from '../../../../src/modules/ingestion/ingestion-types';

const queryAttribute = (to: string, exposed: DataParam['exposed'], defaultValue: string): DataParam => ({
  type: 'data',
  from: 'path',
  to,
  default: defaultValue,
  state_operation: 'replace',
  data_operation: 'data',
  exposed,
});

describe('ingestion-json-domain — configuration export sanitization', () => {
  it('should blank the sensitive header values only', () => {
    expect(sanitizeExportedHeaders([
      { name: 'Accept', value: 'application/json' },
      { name: 'X-Api-Key', value: 'secret-value' },
    ])).toEqual([
      { name: 'Accept', value: 'application/json' },
      { name: 'X-Api-Key', value: '' },
    ]);
  });

  it('should blank the default value of the sensitive query attributes, whatever their exposition', () => {
    expect(sanitizeExportedQueryAttributes([
      queryAttribute('page', 'query_param', '1'),
      queryAttribute('X-Api-Key', 'header', 'header-secret'),
      queryAttribute('api_key', 'query_param', 'query-secret'),
      queryAttribute('auth_token', 'body', 'body-secret'),
    ])).toEqual([
      queryAttribute('page', 'query_param', '1'),
      queryAttribute('X-Api-Key', 'header', ''),
      queryAttribute('api_key', 'query_param', ''),
      queryAttribute('auth_token', 'body', ''),
    ]);
  });

  it('should keep an absent list of query attributes absent', () => {
    expect(sanitizeExportedQueryAttributes(undefined)).toBeUndefined();
  });
});
