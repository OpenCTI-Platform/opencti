import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { DashboardVariable } from '../dashboard-types';
import DashboardVariableChip from './DashboardVariableChip';

// Not mocked here: the chip goes through the real labels hook.
const entityType: DashboardVariable = {
  id: 'var-1',
  name: 'Actor type',
  type: 'entityType',
  restriction: { mode: 'none' },
  defaultValue: null,
};

describe('DashboardVariableChip with an entity type variable', () => {
  it('shows the translated name of the type, not its raw value', () => {
    testRender(<DashboardVariableChip variable={entityType} value="Threat-Actor-Group" usedInWidgetIds={['w-1']} onChange={() => {}} />);
    expect(screen.getByRole('button', { name: 'Actor type : Threat Actor Group' })).toBeInTheDocument();
    expect(screen.queryByText(/Threat-Actor-Group/)).toBeNull();
  });
});
