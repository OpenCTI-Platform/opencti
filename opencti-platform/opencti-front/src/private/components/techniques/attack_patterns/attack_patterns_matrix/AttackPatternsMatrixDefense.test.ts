import { describe, expect, it, vi } from 'vitest';
import type React from 'react';
import { ALL_DEFENSE_LAYERS } from '../../../defense/matrix/defenseMatrix-utils';
import { defenseKeyboardProps, type DefenseMatrixMode } from './AttackPatternsMatrixDefense';

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
