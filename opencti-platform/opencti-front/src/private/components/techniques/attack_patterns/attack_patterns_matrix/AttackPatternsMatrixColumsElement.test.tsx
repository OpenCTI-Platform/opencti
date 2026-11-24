import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import AttackPatternsMatrixColumnsElement from './AttackPatternsMatrixColumsElement';
import type { FilteredSubAttackPattern } from './AttackPatternsMatrixColumns';
import type { CellDecoration } from './attackPatternsMatrixCellDecoration';
import { getMatrixConfig } from './attackPatternsMatrixConfig';

const attackPattern = { attack_pattern_id: 'ap-1059', name: 'Command', description: null, isCovered: true, isOverlapping: true } as unknown as FilteredSubAttackPattern;
const config = getMatrixConfig(undefined, false);
const decoration: CellDecoration = { fill: 'rgb(1, 2, 3)', textTone: 'dark', linkedEntities: [], accessibleName: 'T1059 - Command, 2 procedures' };

describe('AttackPatternsMatrixColumnsElement', () => {
  it('uses the decoration fill and accessible name', () => {
    testRender(<AttackPatternsMatrixColumnsElement config={config} attackPattern={attackPattern} handleOpen={vi.fn()} isSecurityPlatform={false} decoration={decoration} />);
    expect(screen.getByLabelText('T1059 - Command, 2 procedures')).toHaveStyle({ backgroundColor: 'rgb(1, 2, 3)' });
  });
  it('still shows the should-cover icon when decorated', () => {
    testRender(
      <AttackPatternsMatrixColumnsElement
        config={config}
        attackPattern={attackPattern}
        handleOpen={vi.fn()}
        isSecurityPlatform={false}
        attackPatternIdsToOverlap={['ap-1059']}
        decoration={decoration}
      />,
    );
    expect(screen.getByTestId('CheckOutlinedIcon')).toBeInTheDocument();
  });
  it('keeps its usual look without a decoration', () => {
    testRender(<AttackPatternsMatrixColumnsElement config={config} attackPattern={attackPattern} handleOpen={vi.fn()} isSecurityPlatform={false} />);
    expect(screen.queryByLabelText('T1059 - Command, 2 procedures')).not.toBeInTheDocument();
    expect(screen.getByText('Command')).toBeInTheDocument();
  });
  it('draws the should-cover icon in the dark label colour on a heat-filled cell', () => {
    testRender(
      <AttackPatternsMatrixColumnsElement
        config={config}
        attackPattern={{ ...attackPattern, isOverlapping: false } as FilteredSubAttackPattern}
        handleOpen={vi.fn()}
        isSecurityPlatform={false}
        attackPatternIdsToOverlap={[]}
        decoration={decoration}
      />,
    );
    // The error red would vanish on the red end of the heat scale; the icon takes the cell's dark label colour instead.
    expect(screen.getByTestId('CloseOutlinedIcon')).not.toHaveClass('MuiSvgIcon-colorError');
  });
});
