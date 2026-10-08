import { describe, expect, it, vi } from 'vitest';
import type React from 'react';
import { ALL_DEFENSE_LAYERS } from '../../../defense/matrix/defenseMatrix-utils';
import {
  defenseCellLevel,
  defenseCoveredPercent,
  type DefenseMatrixCellData,
  defenseKeyboardProps,
  type DefenseMatrixMode,
  defenseTechniqueLevel,
  isInDefenseLevelFilter,
  isTechniqueInDefenseLevelFilter,
} from './AttackPatternsMatrixDefense';

const keyEvent = (key: string, target: object, currentTarget: object) => ({
  key,
  target,
  currentTarget,
  preventDefault: vi.fn(),
  stopPropagation: vi.fn(),
}) as unknown as React.KeyboardEvent;

const defenseMode = (onSelect: (id: string) => void): DefenseMatrixMode => ({
  cells: new Map(),
  layers: ALL_DEFENSE_LAYERS,
  threatOverlay: false,
  onSelect,
});

describe('Defense matrix tactic coverage', () => {
  const cell = (id: string, level: number) => ({
    attack_pattern_id: id,
    level,
    telemetry: false,
    detection: 'none',
    validated: 'none',
    mitigated: false,
    threats_count: 0,
  }) as unknown as DefenseMatrixCellData;
  const defense: DefenseMatrixMode = {
    ...defenseMode(() => {}),
    cells: new Map([['parent', cell('parent', 0)], ['sub', cell('sub', 3)], ['other', cell('other', 1)]]),
  };

  it('should count a technique at the best level of itself and its sub-techniques', () => {
    expect(defenseTechniqueLevel(defense, ['parent', 'sub'])).toBe(3);
    expect(defenseTechniqueLevel(defense, ['parent'])).toBe(0);
    expect(defenseTechniqueLevel(defense, ['unknown'])).toBe(0);
  });
  it('should count each displayed technique once in the tactic percentage', () => {
    expect(defenseCoveredPercent(defense, [['parent', 'sub']])).toBe(100);
    expect(defenseCoveredPercent(defense, [['parent', 'sub'], ['other']])).toBe(50);
    expect(defenseCoveredPercent(defense, [])).toBe(0);
  });
  it('should filter a counter on the stored levels it counts, whatever layers are shown', () => {
    const validated = { ...cell('validated', 4), detection: 'deployed', validated: 'validated' } as unknown as DefenseMatrixCellData;
    const withoutValidation: DefenseMatrixMode = {
      ...defense,
      cells: new Map([['validated', validated]]),
      layers: { ...ALL_DEFENSE_LAYERS, validated: false },
      levelFilter: [4],
    };
    expect(defenseCellLevel(withoutValidation, 'validated')).toBeLessThan(4);
    expect(isInDefenseLevelFilter(withoutValidation, 'validated')).toBe(true);
    expect(isInDefenseLevelFilter({ ...withoutValidation, levelFilter: [3] }, 'validated')).toBe(false);
    expect(isInDefenseLevelFilter({ ...withoutValidation, levelFilter: null }, 'validated')).toBe(true);
  });
  it('should filter a displayed technique at the best stored level of itself and its sub-techniques, as the counters count it', () => {
    const gaps: DefenseMatrixMode = { ...defense, levelFilter: [0, 1, 2] };
    const deployed: DefenseMatrixMode = { ...defense, levelFilter: [3] };
    // A gap parent with a deployed sub-technique counts as deployed only
    expect(isTechniqueInDefenseLevelFilter(gaps, ['parent', 'sub'])).toBe(false);
    expect(isTechniqueInDefenseLevelFilter(deployed, ['parent', 'sub'])).toBe(true);
    expect(isTechniqueInDefenseLevelFilter(gaps, ['parent'])).toBe(true);
    expect(isTechniqueInDefenseLevelFilter(gaps, ['unknown'])).toBe(true);
    expect(isTechniqueInDefenseLevelFilter({ ...defense, levelFilter: null }, ['parent', 'sub'])).toBe(true);
  });
});

describe('Defense matrix cell keyboard activation', () => {
  it('should open the technique on Enter and Space pressed on the cell itself', () => {
    const onSelect = vi.fn();
    const { onKeyDown } = defenseKeyboardProps(defenseMode(onSelect), 'ap-1');
    const cell = {};
    const enter = keyEvent('Enter', cell, cell);
    onKeyDown(enter);
    onKeyDown(keyEvent(' ', cell, cell));
    expect(onSelect).toHaveBeenCalledTimes(2);
    expect(onSelect).toHaveBeenCalledWith('ap-1');
    expect(enter.preventDefault).toHaveBeenCalled();
  });

  it('should leave the keys pressed on a nested control to that control', () => {
    const onSelect = vi.fn();
    const { onKeyDown } = defenseKeyboardProps(defenseMode(onSelect), 'ap-1');
    const expandButton = keyEvent('Enter', { nested: true }, {});
    onKeyDown(expandButton);
    expect(onSelect).not.toHaveBeenCalled();
    expect(expandButton.preventDefault).not.toHaveBeenCalled();
    expect(expandButton.stopPropagation).not.toHaveBeenCalled();
  });

  it('should ignore other keys', () => {
    const onSelect = vi.fn();
    const cell = {};
    defenseKeyboardProps(defenseMode(onSelect), 'ap-1').onKeyDown(keyEvent('Tab', cell, cell));
    expect(onSelect).not.toHaveBeenCalled();
  });
});
