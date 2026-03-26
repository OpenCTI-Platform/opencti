import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import useEntitySettings from './useEntitySettings';
import useEntityTranslation from './useEntityTranslation';

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

describe('Hook: useEntityTranslation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return custom singular name when set', () => {
    mockEntitySettings([makeSetting('Report', 'Intel Report')]);
    const { translateEntityType } = useEntityTranslation();
    expect(translateEntityType('Report')).toBe('Intel Report');
  });

  it('should return custom plural name when defaultLabel is provided', () => {
    mockEntitySettings([makeSetting('Report', 'Intel Report', 'Intel Reports')]);
    const { translateEntityType } = useEntityTranslation();
    expect(translateEntityType('Report', { plural: true })).toBe('Intel Reports');
  });

  it('should fall back to defaultLabel when custom_name_plural is null', () => {
    mockEntitySettings([makeSetting('Report', null, null)]);
    const { translateEntityType } = useEntityTranslation();
    expect(translateEntityType('Report', { plural: true })).toBe('Reports');
  });

  it('should fall back to i18n when no custom_name and no defaultLabel', () => {
    mockEntitySettings([makeSetting('Report', null)]);
    const { translateEntityType } = useEntityTranslation();
    expect(translateEntityType('Report')).toBe('entity_Report');
  });

  it('should fall back to i18n when no matching setting exists and no defaultLabel', () => {
    mockEntitySettings([makeSetting('Report', 'Intel Report')]);
    const { translateEntityType } = useEntityTranslation();
    expect(translateEntityType('Unknown')).toBe('entity_Unknown');
  });

  it('should find the correct setting among multiple entity settings', () => {
    mockEntitySettings([
      makeSetting('Report', 'Intel Report', 'Intel Reports'),
      makeSetting('Malware', 'Custom Malware', 'Custom Malwares'),
    ]);
    const { translateEntityType } = useEntityTranslation();
    expect(translateEntityType('Malware')).toBe('Custom Malware');
    expect(translateEntityType('Report')).toBe('Intel Report');
  });
});
