import { describe, expect, it } from 'vitest';
import {
  buildExportFileName,
  formatExportUtcTimestamp,
  normalizeExportSourceEntityName,
  normalizeMarkingForFileName,
  sanitizeFileNamePart,
} from './StixCoreObjectFileExportForm.utils';

describe('StixCoreObjectFileExportForm utils', () => {
  it('sanitizes and truncates entity name to 100 chars', () => {
    const sourceName = `${'A'.repeat(120)} / report`;

    const sanitized = sanitizeFileNamePart(sourceName, 'Entity', 100);

    expect(sanitized.length).toBe(100);
    expect(sanitized).toBe('A'.repeat(100));
  });

  it('returns fallback entity name when empty', () => {
    expect(sanitizeFileNamePart('   ', 'Entity', 100)).toBe('Entity');
  });

  it('formats timestamp in UTC as YYYYMMDDTHHmmZ', () => {
    expect(formatExportUtcTimestamp('2026-05-25T13:55:10+02:00')).toBe('20260525T1155Z');
  });

  it('normalizes TLP:AMBER to TLP-AMBER', () => {
    expect(normalizeMarkingForFileName([{ label: 'TLP:AMBER', value: 'id-1' }])).toBe('TLP-AMBER');
  });

  it('normalizes TLP:AMBER+STRICT replacing + with -', () => {
    expect(normalizeMarkingForFileName([{ label: 'TLP:AMBER+STRICT', value: 'id-1' }])).toBe('TLP-AMBER-STRICT');
  });

  it('normalizes a PAP marking replacing : with -', () => {
    expect(normalizeMarkingForFileName([{ label: 'PAP:RED', value: 'id-2' }])).toBe('PAP-RED');
  });

  it('collapses multiple consecutive separators into a single -', () => {
    expect(normalizeMarkingForFileName([{ label: 'TLP::AMBER  STRICT', value: 'id-3' }])).toBe('TLP-AMBER-STRICT');
  });

  it('preserves marking already in correct TLP-XXXX format', () => {
    expect(normalizeMarkingForFileName([{ label: 'TLP-GREEN', value: 'id-4' }])).toBe('TLP-GREEN');
  });

  it('normalizes marking and truncates it to 100 chars', () => {
    const marking = [{ label: `TLP:AMBER-${'X'.repeat(120)}`, value: 'id-5' }];

    const normalized = normalizeMarkingForFileName(marking);

    expect(normalized?.startsWith('TLP-AMBER-')).toBe(true);
    expect(normalized?.length).toBe(100);
  });

  it('returns null when there is no marking', () => {
    expect(normalizeMarkingForFileName([])).toBeNull();
    expect(normalizeMarkingForFileName(undefined)).toBeNull();
  });

  it('builds default export file name with marking', () => {
    const fileName = buildExportFileName({
      entityName: 'APT29 Campaign Analysis',
      utcIsoDate: '2026-05-21T13:55:10Z',
      markings: [{ label: 'TLP:AMBER', value: 'marking--amber' }],
    });

    expect(fileName).toBe('APT29_Campaign_Analysis_20260521T1355Z_TLP-AMBER');
  });

  it('builds default export file name without marking segment when no marking', () => {
    const fileName = buildExportFileName({
      entityName: 'My report',
      utcIsoDate: '2026-05-21T13:55:10Z',
      markings: [],
    });

    expect(fileName).toBe('My_report_20260521T1355Z');
  });

  it('falls back to Export when entity name is missing', () => {
    const fileName = buildExportFileName({
      entityName: null,
      utcIsoDate: '2026-05-21T13:55:10Z',
      markings: [{ label: 'TLP:CLEAR', value: 'marking--clear' }],
    });

    expect(fileName).toBe('Export_20260521T1355Z_TLP-CLEAR');
  });

  it('normalizes source file name by removing extension only for plain files', () => {
    expect(normalizeExportSourceEntityName('petit coincoin.html')).toBe('petit coincoin');
  });

  it('normalizes source file name by stripping existing export timestamp and marking suffix', () => {
    expect(normalizeExportSourceEntityName('petit_coincoin_20260526T1015Z_TLP-RED.html')).toBe('petit_coincoin');
  });

  it('normalizes source file name by stripping existing export timestamp suffix without marking', () => {
    expect(normalizeExportSourceEntityName('petit_coincoin_20260526T1015Z.md')).toBe('petit_coincoin');
  });
});
