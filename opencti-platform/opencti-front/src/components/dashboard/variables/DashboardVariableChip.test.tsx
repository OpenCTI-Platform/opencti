import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { DashboardVariable } from '../dashboard-types';
import DashboardVariableChip from './DashboardVariableChip';

const mockLabels = vi.hoisted(() => ({
  current: undefined as ((values: string[]) => { labels: Map<string, string>; restricted: Set<string> }) | undefined,
}));

vi.mock('./useVariableValueLabels', () => ({
  default: (_variable: unknown, values: string[]) => (mockLabels.current
    ? mockLabels.current(values)
    : { labels: new Map(values.map((value) => [value, value])), restricted: new Set() }),
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

  it('shows the value of a date variable as a readable date, not as its raw ISO string', () => {
    const since: DashboardVariable = { id: 'var-3', name: 'Since', type: 'date', restriction: { mode: 'none' }, defaultValue: null };
    renderChip({ variable: since, value: '2026-01-01T00:00:00.000Z' });
    const chip = screen.getByTestId('dashboard-variable-chip-Since');
    expect(chip).toHaveTextContent(/Since : .*2026/);
    expect(chip).not.toHaveTextContent('T00:00:00');
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

  it('is inert when disabled: it cannot be clicked open and its value cannot change', async () => {
    const { user, onChange } = renderChip({ disabled: true });
    const chip = screen.getByRole('button', { name: 'Sector : Energy' });
    expect(chip).toBeDisabled();
    await user.click(chip);
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    expect(onChange).not.toHaveBeenCalled();
  });

  it('closes its value input when it becomes disabled', async () => {
    const { user, rerender } = renderChip();
    await user.click(screen.getByRole('button', { name: 'Sector : Energy' }));
    expect(screen.getByRole('textbox')).toBeInTheDocument();
    rerender(<DashboardVariableChip variable={sector} value="Energy" usedInWidgetIds={['w-1']} onChange={() => {}} disabled />);
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
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

  it('warns, stays clickable and explains on hover when the default value is not valid', async () => {
    const { user } = renderChip({ hasInvalidDefault: true });
    const chip = screen.getByTestId('dashboard-variable-chip-Sector');
    expect(chip).toHaveAttribute('data-invalid-default', 'true');
    const button = within(chip).getByRole('button', { name: 'Sector : Energy' });
    expect(button).toBeEnabled();
    // Distinct from the critical state of a Restricted value.
    expect(button.className).not.toMatch(/feedback-error/);
    await user.hover(button);
    expect((await screen.findAllByText('The default value of this variable is not valid: the widgets that use it show no data')).length).toBeGreaterThan(0);
    await user.click(button);
    expect(screen.getByRole('textbox')).toBeInTheDocument();
  });

  it('shows the warning rather than the unused explanation when both apply', async () => {
    const { user } = renderChip({ hasInvalidDefault: true, usedInWidgetIds: [] });
    const chip = screen.getByTestId('dashboard-variable-chip-Sector');
    expect(chip).toHaveAttribute('data-invalid-default', 'true');
    expect(chip).toHaveAttribute('data-unused', 'true');
    await user.hover(within(chip).getByRole('button', { name: 'Sector : Energy' }));
    expect((await screen.findAllByText(/The default value of this variable is not valid/)).length).toBeGreaterThan(0);
    expect(screen.queryByText('Not used by any widget')).not.toBeInTheDocument();
  });

  it('shows no warning when the default value is valid', async () => {
    const { user } = renderChip();
    const chip = screen.getByTestId('dashboard-variable-chip-Sector');
    expect(chip).not.toHaveAttribute('data-invalid-default');
    await user.hover(within(chip).getByRole('button', { name: 'Sector : Energy' }));
    expect(screen.queryByText(/The default value of this variable is not valid/)).not.toBeInTheDocument();
  });

  it('turns critical and reads Restricted when the value cannot be resolved', () => {
    mockLabels.current = (values) => ({ labels: new Map(values.map((value) => [value, 'Restricted'])), restricted: new Set(values) });
    renderChip({ variable: org, value: 'unknown-id' });
    const chip = screen.getByRole('button', { name: 'Org : Restricted' });
    expect(chip.className).toMatch(/feedback-error/);
    expect(screen.queryByText(/unknown-id/)).not.toBeInTheDocument();
  });

  it('stays neutral for an entity that is really named Restricted', () => {
    mockLabels.current = (values) => ({ labels: new Map(values.map((value) => [value, 'Restricted'])), restricted: new Set() });
    renderChip({ variable: org, value: 'entity-id' });
    const chip = screen.getByRole('button', { name: 'Org : Restricted' });
    expect(chip.className).not.toMatch(/feedback-error/);
  });

  it('stays neutral while the id is still resolving', () => {
    mockLabels.current = () => ({ labels: new Map(), restricted: new Set() });
    renderChip({ variable: org, value: 'some-id' });
    const chip = screen.getByRole('button', { name: 'Org : …' });
    expect(chip.className).not.toMatch(/feedback-error/);
    expect(screen.queryByText(/some-id/)).not.toBeInTheDocument();
  });

  it('shows a placeholder when the variable has no value', () => {
    renderChip({ variable: org, value: undefined });
    expect(screen.getByRole('button', { name: 'Org : Not set' })).toBeInTheDocument();
  });

  it('has no menu button: the actions live in the value popover', () => {
    renderChip({ onEdit: vi.fn(), onDelete: vi.fn() });
    expect(screen.queryByRole('button', { name: /Open menu/ })).not.toBeInTheDocument();
    expect(screen.queryByTestId('dashboard-variable-edit')).not.toBeInTheDocument();
    expect(screen.queryByTestId('dashboard-variable-delete')).not.toBeInTheDocument();
  });

  it('offers no action in the popover unless an edit or delete callback is provided', async () => {
    const { user } = renderChip();
    await user.click(screen.getByRole('button', { name: 'Sector : Energy' }));
    expect(screen.getByRole('textbox')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit variable' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete variable' })).not.toBeInTheDocument();
  });

  it('offers only the provided actions, and closes the popover when one is used', async () => {
    const onEdit = vi.fn();
    const { user } = renderChip({ onEdit });
    await user.click(screen.getByRole('button', { name: 'Sector : Energy' }));
    expect(screen.queryByTestId('dashboard-variable-delete')).not.toBeInTheDocument();
    await user.click(screen.getByTestId('dashboard-variable-edit'));
    expect(onEdit).toHaveBeenCalledWith(sector);
    await waitFor(() => expect(screen.queryByRole('textbox')).not.toBeInTheDocument());
  });

  it('offers delete when a delete callback is provided', async () => {
    const onDelete = vi.fn();
    const { user } = renderChip({ onDelete });
    await user.click(screen.getByRole('button', { name: 'Sector : Energy' }));
    expect(screen.queryByTestId('dashboard-variable-edit')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Delete variable' }));
    expect(onDelete).toHaveBeenCalledWith(sector);
    await waitFor(() => expect(screen.queryByRole('textbox')).not.toBeInTheDocument());
  });
});
