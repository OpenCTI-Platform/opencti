import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { DashboardVariable } from '../dashboard-types';
import DashboardVariableChip from './DashboardVariableChip';

const mockLabels = vi.hoisted(() => ({ current: undefined as ((values: string[]) => Map<string, string>) | undefined }));

vi.mock('./useVariableValueLabels', () => ({
  default: (_variable: unknown, values: string[]) => (mockLabels.current
    ? mockLabels.current(values)
    : new Map(values.map((value) => [value, value]))),
}));

const sector: DashboardVariable = {
  id: 'var-1',
  name: 'Sector',
  type: 'text',
  restriction: { mode: 'none' },
  defaultValue: 'Energy',
};
const org: DashboardVariable = {
  id: 'var-2',
  name: 'Org',
  type: 'entity',
  entityTypes: ['Organization'],
  restriction: { mode: 'none' },
  defaultValue: null,
};

const renderChip = (props: Partial<React.ComponentProps<typeof DashboardVariableChip>> = {}) => {
  const onChange = vi.fn();
  const rendered = testRender(
    <DashboardVariableChip variable={sector} value="Energy" usedInWidgetIds={['w-1']} onChange={onChange} {...props} />,
  );
  return { ...rendered, onChange };
};

describe('DashboardVariableChip', () => {
  beforeEach(() => {
    mockLabels.current = undefined;
  });

  it('labels the chip with the name and the value', () => {
    renderChip();
    expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeInTheDocument();
    expect(screen.getByTestId('dashboard-variable-chip-Sector')).toHaveAttribute('data-unused', 'false');
  });

  it('opens the value input on click and forwards the typed value', async () => {
    const { user, onChange } = renderChip({ value: undefined });
    await user.click(screen.getByRole('button', { name: 'Sector : Not set' }));
    await user.click(screen.getByRole('textbox'));
    await user.paste('Finance');
    expect(onChange).not.toHaveBeenCalled();
    await user.tab();
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenLastCalledWith('Finance');
  });

  it('mutes the chip and explains why on hover when no widget uses the variable', async () => {
    const { user } = renderChip({ usedInWidgetIds: [] });
    const chip = screen.getByTestId('dashboard-variable-chip-Sector');
    expect(chip).toHaveAttribute('data-unused', 'true');
    expect(chip).toHaveStyle({ opacity: '0.6' });
    await user.hover(within(chip).getByRole('button', { name: 'Sector : Energy' }));
    expect((await screen.findAllByText('Not used by any widget')).length).toBeGreaterThan(0);
  });

  it('does not mute nor explain a used variable', async () => {
    const { user } = renderChip();
    const chip = screen.getByTestId('dashboard-variable-chip-Sector');
    expect(chip).not.toHaveStyle({ opacity: '0.6' });
    await user.hover(within(chip).getByRole('button', { name: 'Sector : Energy' }));
    expect(screen.queryByText('Not used by any widget')).not.toBeInTheDocument();
  });

  it('turns critical and reads Restricted when the value cannot be resolved', () => {
    mockLabels.current = (values) => new Map(values.map((value) => [value, 'Restricted']));
    renderChip({ variable: org, value: 'unknown-id' });
    const chip = screen.getByRole('button', { name: 'Org : Restricted' });
    expect(chip.className).toMatch(/feedback-error/);
    expect(screen.queryByText(/unknown-id/)).not.toBeInTheDocument();
  });

  it('stays neutral while the id is still resolving', () => {
    mockLabels.current = () => new Map();
    renderChip({ variable: org, value: 'some-id' });
    const chip = screen.getByRole('button', { name: 'Org : …' });
    expect(chip.className).not.toMatch(/feedback-error/);
    expect(screen.queryByText(/some-id/)).not.toBeInTheDocument();
  });

  it('shows a placeholder when the variable has no value', () => {
    renderChip({ variable: org, value: undefined });
    expect(screen.getByRole('button', { name: 'Org : Not set' })).toBeInTheDocument();
  });

  it('has no menu unless an edit or delete callback is provided', () => {
    renderChip();
    expect(screen.queryByRole('button', { name: /Open menu/ })).not.toBeInTheDocument();
  });

  it('offers only the provided menu actions', async () => {
    const onEdit = vi.fn();
    const { user } = renderChip({ onEdit });
    await user.click(screen.getByRole('button', { name: 'Open menu: Sector' }));
    await user.click(screen.getByRole('menuitem', { name: 'Edit variable' }));
    expect(onEdit).toHaveBeenCalledWith(sector);
  });

  it('offers delete when a delete callback is provided', async () => {
    const onDelete = vi.fn();
    const { user } = renderChip({ onDelete });
    await user.click(screen.getByRole('button', { name: 'Open menu: Sector' }));
    expect(screen.queryByRole('menuitem', { name: 'Edit variable' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('menuitem', { name: 'Delete variable' }));
    expect(onDelete).toHaveBeenCalledWith(sector);
  });
});
