import { fireEvent, render, screen } from '@testing-library/react';
import { createTheme, ThemeOptions, ThemeProvider } from '@mui/material/styles';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ThemeDark from '../../../../components/ThemeDark';
import InvestigationCreationFromSelection from './InvestigationCreationFromSelection';

const { createInvestigation, mutationState } = vi.hoisted(() => ({
  createInvestigation: vi.fn(),
  mutationState: { creating: false },
}));

vi.mock('./useCreateInvestigationFromSelection', () => ({
  default: () => ({ createInvestigation, creating: mutationState.creating }),
}));

const testTheme = createTheme(ThemeDark() as ThemeOptions);

const renderComponent = (disabled: boolean, entityIds: string[]) => render(
  <ThemeProvider theme={testTheme}>
    <InvestigationCreationFromSelection
      disabled={disabled}
      entityIds={entityIds}
    />
  </ThemeProvider>,
);

describe('InvestigationCreationFromSelection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mutationState.creating = false;
  });

  it('starts an investigation with the supplied entity ids', () => {
    renderComponent(false, ['entity--1', 'relationship--2']);

    fireEvent.click(screen.getByRole('button', { name: 'Start an investigation' }));

    expect(createInvestigation).toHaveBeenCalledWith(['entity--1', 'relationship--2']);
  });

  it('does not start an investigation when disabled', () => {
    renderComponent(true, ['entity--1']);

    fireEvent.click(screen.getByRole('button', { name: 'Start an investigation' }));

    expect(createInvestigation).not.toHaveBeenCalled();
  });

  it('does not start another investigation while one is being created', () => {
    mutationState.creating = true;
    renderComponent(false, ['entity--1']);

    fireEvent.click(screen.getByRole('button', { name: 'Start an investigation' }));

    expect(createInvestigation).not.toHaveBeenCalled();
  });
});
