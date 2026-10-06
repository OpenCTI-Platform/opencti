import React from 'react';
import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import { DefenseLevelsBar } from './DefenseLevelsBar';

const LEVELS = [2, 1, 1, 0, 0];
const COUNTS = 'No coverage: 2 techniques (50%), Telemetry only: 1 technique (25%), Detection available: 1 technique (25%), '
  + 'Detection deployed: 0 techniques (0%), Detection validated: 0 techniques (0%)';

describe('Defense levels bar', () => {
  it('reads the count of every level', () => {
    testRender(<DefenseLevelsBar levels={LEVELS} />);
    expect(screen.getByRole('img').getAttribute('aria-label')).toBe(COUNTS);
  });

  it('keeps the count of every level after a custom summary', () => {
    testRender(<DefenseLevelsBar levels={LEVELS} label="Execution: 0 of 4 techniques covered" />);
    expect(screen.getByRole('img').getAttribute('aria-label')).toBe(`Execution: 0 of 4 techniques covered. ${COUNTS}`);
  });
});
