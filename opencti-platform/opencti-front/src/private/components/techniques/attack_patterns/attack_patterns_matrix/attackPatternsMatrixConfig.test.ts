import { describe, it, expect } from 'vitest';
import { compareByMitreId, getMatrixConfig, MatrixTechniqueLike } from './attackPatternsMatrixConfig';

const t = (name: string, x_mitre_id?: string | null): MatrixTechniqueLike => ({ name, x_mitre_id });
const sortedIds = (items: MatrixTechniqueLike[]) => [...items].sort(compareByMitreId).map((i) => i.x_mitre_id ?? i.name);

describe('getMatrixConfig', () => {
  describe('default variant (regression lock)', () => {
    const config = getMatrixConfig(undefined, false);

    it('labels a technique with its name only', () => {
      expect(config.formatLabel(t('Phishing', 'T1566'))).toBe('Phishing');
    });

    it('sorts by name with localeCompare', () => {
      const sorted = [t('b'), t('a')].sort(config.compareTechniques).map((i) => i.name);
      expect(sorted).toEqual(['a', 'b']);
    });

    it('has no badge colour override', () => {
      expect(config.badgeColors).toBeUndefined();
    });

    it('allows adding outside of coverage mode', () => {
      expect(config.canAdd).toBe(true);
    });

    it('has no keyboard cells', () => {
      expect(config.keyboardCells).toBe(false);
    });

    it('does not allow adding in coverage mode', () => {
      expect(getMatrixConfig(undefined, true).canAdd).toBe(false);
    });

    it('keeps sub-techniques in API order', () => {
      expect(config.sortSubTechniques).toBe(false);
      expect(getMatrixConfig('default', false).sortSubTechniques).toBe(false);
    });
  });

  describe('investigation variant', () => {
    const config = getMatrixConfig('investigation', false);

    it('labels a technique with its MITRE ID and name', () => {
      expect(config.formatLabel(t('Phishing', 'T1566'))).toBe('T1566 - Phishing');
    });

    it('labels a technique with its name only when there is no ID', () => {
      expect(config.formatLabel(t('Phishing'))).toBe('Phishing');
    });

    it('does not allow adding', () => {
      expect(config.canAdd).toBe(false);
    });

    it('has keyboard cells', () => {
      expect(config.keyboardCells).toBe(true);
    });

    it('sorts sub-techniques', () => {
      expect(config.sortSubTechniques).toBe(true);
    });

    it('uses neutral badge colours', () => {
      expect(config.badgeColors).toEqual({ color: 'var(--gray-800)', textColor: 'var(--gray-100)' });
    });

    it('sorts by MITRE ID', () => {
      const sorted = [t('B', 'T1548'), t('A', 'T1078')].sort(config.compareTechniques);
      expect(sorted.map((i) => i.x_mitre_id)).toEqual(['T1078', 'T1548']);
    });
  });
});

describe('compareByMitreId', () => {
  it('sorts by main number', () => {
    expect(sortedIds([t('b', 'T1548'), t('a', 'T1078')])).toEqual(['T1078', 'T1548']);
  });

  it('sorts a parent before its sub-techniques, then by sub number', () => {
    expect(sortedIds([t('c', 'T1074.004'), t('b', 'T1074.001'), t('a', 'T1074')]))
      .toEqual(['T1074', 'T1074.001', 'T1074.004']);
  });

  it('sorts numerically rather than lexically', () => {
    expect(sortedIds([t('b', 'T1000'), t('a', 'T999')])).toEqual(['T999', 'T1000']);
  });

  it('sorts missing or non-matching IDs after every T ID, then by name', () => {
    const sorted = [t('Zeta'), t('Alpha', 'CAPEC-1'), t('Mid', 'T1'), t('Beta', null)].sort(compareByMitreId);
    expect(sorted.map((i) => i.name)).toEqual(['Mid', 'Alpha', 'Beta', 'Zeta']);
  });

  it('sorts equal IDs by name', () => {
    const sorted = [t('b', 'T1059'), t('a', 'T1059')].sort(compareByMitreId);
    expect(sorted.map((i) => i.name)).toEqual(['a', 'b']);
  });
});
