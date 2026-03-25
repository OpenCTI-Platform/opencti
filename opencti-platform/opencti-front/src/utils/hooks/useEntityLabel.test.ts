import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import useEntitySettings from './useEntitySettings';
import { useEntityLabelResolver } from './useEntityLabel';

vi.mock('./useEntitySettings', () => ({ default: vi.fn() }));
vi.mock('../../components/i18n', () => ({
  useFormatter: vi.fn(() => ({ t_i18n: vi.fn((key: string) => key) })),
}));

const mockEntitySettings = (settings: Record<string, unknown>[]) => {
  (useEntitySettings as Mock).mockReturnValue(settings);
};

const makeSetting = (
  targetType: string,
  customName: string | null = null,
  customNamePlural: string | null = null,
) => ({
  target_type: targetType,
  custom_name: customName,
  custom_name_plural: customNamePlural,
});

describe('Hook: useEntityLabelResolver', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return custom singular name when set', () => {
    mockEntitySettings([makeSetting('Report', 'Intel Report')]);
    const resolve = useEntityLabelResolver();
    expect(resolve('Report')).toBe('Intel Report');
  });

  it('should return custom plural name when defaultLabel is provided', () => {
    mockEntitySettings([makeSetting('Report', 'Intel Report', 'Intel Reports')]);
    const resolve = useEntityLabelResolver();
    expect(resolve('Report', 'Reports')).toBe('Intel Reports');
  });

  it('should fall back to defaultLabel when custom_name_plural is null', () => {
    mockEntitySettings([makeSetting('Report', null, null)]);
    const resolve = useEntityLabelResolver();
    expect(resolve('Report', 'Reports')).toBe('Reports');
  });

  it('should fall back to i18n when no custom_name and no defaultLabel', () => {
    mockEntitySettings([makeSetting('Report', null)]);
    const resolve = useEntityLabelResolver();
    expect(resolve('Report')).toBe('entity_Report');
  });

  it('should fall back to i18n when no matching setting exists and no defaultLabel', () => {
    mockEntitySettings([makeSetting('Report', 'Intel Report')]);
    const resolve = useEntityLabelResolver();
    expect(resolve('Unknown')).toBe('entity_Unknown');
  });

  it('should fall back to defaultLabel when no matching setting exists', () => {
    mockEntitySettings([makeSetting('Report', 'Intel Report')]);
    const resolve = useEntityLabelResolver();
    expect(resolve('Unknown', 'Unknowns')).toBe('Unknowns');
  });

  it('should find the correct setting among multiple entity settings', () => {
    mockEntitySettings([
      makeSetting('Report', 'Intel Report', 'Intel Reports'),
      makeSetting('Malware', 'Custom Malware', 'Custom Malwares'),
    ]);
    const resolve = useEntityLabelResolver();
    expect(resolve('Malware')).toBe('Custom Malware');
    expect(resolve('Report')).toBe('Intel Report');
  });
});
