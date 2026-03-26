import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import useEntitySettings from './useEntitySettings';
import useEntityTranslation from './useEntityTranslation';
import { useFormatter } from '../../components/i18n';

vi.mock('./useEntitySettings', () => ({ default: vi.fn() }));
vi.mock('../../components/i18n', () => ({
  useFormatter: vi.fn().mockReturnValue({ t_i18n: (key: string) => key }),
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

const mockI18n = (entries: { [key: string]: string }) => {
  (useFormatter as Mock).mockReturnValue(({
    t_i18n: (key: string) => key in entries ? entries[key] : key,
  }));
};

describe('Hook: useEntityTranslation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return custom singular name when set', () => {
    mockEntitySettings([makeSetting('Report', 'Intel Report')]);
    const { translateEntityType } = useEntityTranslation();
    expect(translateEntityType('Report')).toBe('Intel Report');
  });

  it('should return custom plural name when set', () => {
    mockEntitySettings([makeSetting('Report', 'Intel Report', 'Intel Reports')]);
    const { translateEntityType } = useEntityTranslation();
    expect(translateEntityType('Report', { plural: true })).toBe('Intel Reports');
  });

  it('should fall back to default plural translation when no custom plural', () => {
    mockEntitySettings([makeSetting('Report', null, null)]);
    mockI18n({ entity_plural_Report: 'Reports' });
    const { translateEntityType } = useEntityTranslation();
    expect(translateEntityType('Report', { plural: true })).toBe('Reports');
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

  it('should fall back to i18n when no matching setting exists', () => {
    mockEntitySettings([makeSetting('Report', 'Intel Report')]);
    mockI18n({ entity_plural_Report: 'Reports' });
    const { translateEntityType } = useEntityTranslation();
    expect(translateEntityType('Unknown')).toBe('Unknown');
  });
});
