import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import DashboardPresetField from './DashboardPresetField';

const QUERY = 'DashboardPresetFieldQuery';
const presets = [{ id: 'p1', name: 'Energy' }, { id: 'p2', name: 'Finance' }];

const renderField = (props: Partial<React.ComponentProps<typeof DashboardPresetField>> = {}) => {
  const onChange = vi.fn();
  const rendered = testRender(<DashboardPresetField dashboardId="dashboard-1" value={null} onChange={onChange} {...props} />, {
    userContext: createMockUserContext({ me: { id: 'user-1', name: 'admin' } }),
  });
  const resolve = () => act(() => {
    const operation = rendered.relayEnv.mock.getAllOperations().find((op) => op.request.node.operation.name === QUERY);
    if (operation) rendered.relayEnv.mock.resolve(operation, { data: { workspace: { id: 'dashboard-1', presets } } });
  });
  return { ...rendered, onChange, resolve };
};

describe('DashboardPresetField', () => {
  it('renders nothing without a dashboard', () => {
    renderField({ dashboardId: null });
    expect(screen.queryByTestId('dashboard-preset-field')).toBeNull();
  });

  it('lists the presets of the dashboard and reports the choice, No preset included', async () => {
    const { user, onChange, resolve } = renderField({ value: 'p2' });
    resolve();
    const trigger = await screen.findByRole('combobox');
    expect(trigger).toHaveTextContent('Finance');
    await user.click(trigger);
    await user.click(await screen.findByRole('option', { name: 'Energy' }));
    expect(onChange).toHaveBeenLastCalledWith('p1');
    // The clear control of the library select stands for No preset
    await user.click(screen.getByRole('button', { name: 'No preset' }));
    expect(onChange).toHaveBeenLastCalledWith(null);
  });

  it('shows a preset that no longer exists as none', async () => {
    const { resolve } = renderField({ value: 'deleted' });
    resolve();
    const trigger = await screen.findByRole('combobox');
    expect(trigger).toHaveTextContent(/No preset/);
  });
});
