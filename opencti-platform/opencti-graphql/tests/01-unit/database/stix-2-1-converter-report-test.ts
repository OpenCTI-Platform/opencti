import { describe, it, expect } from 'vitest';
import '../../../src/modules/index';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import type { StixReport } from '../../../src/types/stix-2-1-sdo';
import { REPORT_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/report';

// Regression test for #17947: Report updates silently dropped when published
// is the epoch placeholder (1970-01-01).
describe('STIX 2.1 converter - Report published date', () => {
  it('should preserve epoch published date on Report', () => {
    const reportWithEpoch = {
      ...REPORT_INSTANCE,
      published: '1970-01-01T00:00:00.000Z',
    };
    const stix = convertStoreToStix_2_1(reportWithEpoch as any) as StixReport;
    expect(stix.published).toBe('1970-01-01T00:00:00.000Z');
  });

  it('should preserve standard published date on Report', () => {
    const stix = convertStoreToStix_2_1(REPORT_INSTANCE as any) as StixReport;
    expect(stix.published).toBe('2025-06-26T14:32:10.000Z');
  });
});
