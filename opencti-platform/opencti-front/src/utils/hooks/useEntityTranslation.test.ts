import { renderHook } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import useEntityTranslation from './useEntityTranslation';

// Mock translations: only some keys have a translation.
const translations: Record<string, string> = {
  entity_Malware: 'Logiciel malveillant',
  entity_Report: 'Rapport',
  relationship_targets: 'cible',
};

vi.mock('../../components/i18n', () => ({
  useFormatter: () => ({
    t_i18n: (key: string) => translations[key] ?? key,
  }),
}));

describe('useEntityTranslation', () => {
  const setup = () => renderHook(() => useEntityTranslation());

  describe('translateEntityType', () => {
    it('should return entity translation when entity_ prefix matches', () => {
      const { result } = setup();
      expect(result.current.translateEntityType('Malware')).toBe('Logiciel malveillant');
      expect(result.current.translateEntityType('Report')).toBe('Rapport');
    });

    it('should return relationship translation when relationship_ prefix matches', () => {
      const { result } = setup();
      expect(result.current.translateEntityType('targets')).toBe('cible');
    });

    it('should fall back to t_i18n(type) when neither entity_ nor relationship_ prefix matches', () => {
      const { result } = setup();
      // 'unknown-type' has no entity_ or relationship_ translation,
      // so it falls through to t_i18n('unknown-type') which returns the key itself.
      expect(result.current.translateEntityType('unknown-type')).toBe('unknown-type');
    });

    it('should return the input as-is for an empty string', () => {
      const { result } = setup();
      expect(result.current.translateEntityType('')).toBe('');
    });
  });
});
