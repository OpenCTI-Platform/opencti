import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { DashboardVariable } from '../dashboard-types';
import { EXPORT_REMOVE_CLASS } from '../../../utils/Image';
import DashboardVariablesBar from './DashboardVariablesBar';

vi.mock('./useVariableValueLabels', () => ({
  default: (_variable: unknown, values: string[]) => new Map(values.map((value) => [value, value])),
}));

const sector: DashboardVariable = {
  id: 'var-1',
  name: 'Sector',
  type: 'text',
  restriction: { mode: 'none' },
  defaultValue: 'Energy',
};
const country: DashboardVariable = {
  id: 'var-2',
  name: 'Country',
  type: 'text',
  restriction: { mode: 'none' },
  defaultValue: null,
};

type BarProps = React.ComponentProps<typeof DashboardVariablesBar>;

const renderBar = (props: Partial<BarProps> = {}) => {
  const handlers = {
    onSetValue: vi.fn(),
    onReset: vi.fn(),
    onSetAsDefaults: vi.fn().mockResolvedValue(undefined),
  };
  const rendered = testRender(
    <DashboardVariablesBar
      variables={[sector, country]}
      values={new Map([['var-1', 'Energy']])}
      defaults={new Map([['var-1', 'Energy']])}
      usedInWidgetIdsByVariable={new Map([['var-1', ['w-1']], ['var-2', ['w-1']]])}
      canManage={false}
      {...handlers}
      {...props}
    />,
  );
  return { ...rendered, ...handlers };
};

describe('DashboardVariablesBar', () => {
  it('renders one chip per variable, a variable without value reading Not set', () => {
    renderBar();
    expect(screen.getByTestId('dashboard-variables-bar')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Country : Not set' })).toBeInTheDocument();
  });

  it('mutes the chip of a variable no widget uses, and one the page knows nothing about', () => {
    renderBar({ usedInWidgetIdsByVariable: new Map([['var-1', []]]) });
    expect(screen.getByTestId('dashboard-variable-chip-Sector')).toHaveAttribute('data-unused', 'true');
    expect(screen.getByTestId('dashboard-variable-chip-Country')).toHaveAttribute('data-unused', 'true');
  });

  it('calls onSetValue with the variable id and the new value, and nothing else', async () => {
    const { user, onSetValue, onReset, onSetAsDefaults } = renderBar();
    await user.click(screen.getByRole('button', { name: 'Country : Not set' }));
    await user.click(screen.getByRole('textbox'));
    await user.paste('France');
    await user.tab();
    expect(onSetValue).toHaveBeenLastCalledWith('var-2', 'France');
    expect(onReset).not.toHaveBeenCalled();
    expect(onSetAsDefaults).not.toHaveBeenCalled();
  });

  it('hides Reset and Set as default values while nothing differs from the defaults', () => {
    renderBar({ canManage: true });
    expect(screen.queryByRole('button', { name: 'Reset' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Set as default values' })).not.toBeInTheDocument();
  });

  it('treats a null default and an empty value as equal', () => {
    renderBar({ canManage: true, values: new Map([['var-1', 'Energy'], ['var-2', '']]) });
    expect(screen.queryByRole('button', { name: 'Reset' })).not.toBeInTheDocument();
  });

  it('shows Reset to a viewer when a value differs, and never Set as default values', async () => {
    const { user, onReset } = renderBar({ values: new Map([['var-1', 'Finance']]) });
    expect(screen.queryByRole('button', { name: 'Set as default values' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Reset' }));
    expect(onReset).toHaveBeenCalledTimes(1);
  });

  it('lets a manager set the current values as defaults, and disables the actions meanwhile', async () => {
    let finish: () => void = () => {};
    const onSetAsDefaults = vi.fn(() => new Promise<void>((resolve) => {
      finish = resolve;
    }));
    const { user } = renderBar({ canManage: true, values: new Map([['var-2', 'France']]), onSetAsDefaults });
    await user.click(screen.getByRole('button', { name: 'Set as default values' }));
    expect(onSetAsDefaults).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Set as default values' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Reset' })).toBeDisabled();
    finish();
    expect(await screen.findByRole('button', { name: 'Reset' })).toBeEnabled();
  });

  it('marks the action buttons for removal from an image export, not the chips', () => {
    renderBar({ canManage: true, onCreate: vi.fn(), values: new Map([['var-1', 'Energy'], ['var-2', 'France']]) });
    expect(screen.getByRole('button', { name: 'Reset' }).closest(`.${EXPORT_REMOVE_CLASS}`)).not.toBeNull();
    expect(screen.getByRole('button', { name: 'Set as default values' }).closest(`.${EXPORT_REMOVE_CLASS}`)).not.toBeNull();
    expect(screen.getByTestId('create-variable-button').closest(`.${EXPORT_REMOVE_CLASS}`)).not.toBeNull();
    expect(screen.getByRole('button', { name: 'Sector : Energy' }).closest(`.${EXPORT_REMOVE_CLASS}`)).toBeNull();
  });

  describe('create button', () => {
    it('is rendered only when a create callback is provided', async () => {
      const onCreate = vi.fn();
      const { user, unmount } = renderBar({ canManage: true, onCreate });
      await user.click(screen.getByTestId('create-variable-button'));
      expect(onCreate).toHaveBeenCalledTimes(1);
      unmount();
      renderBar({ canManage: true });
      expect(screen.queryByTestId('create-variable-button')).not.toBeInTheDocument();
    });

    it('lets a manager call to action show on a dashboard without any variable', () => {
      renderBar({ variables: [], canManage: true, onCreate: vi.fn() });
      expect(screen.getByTestId('dashboard-variables-bar')).toBeInTheDocument();
      expect(screen.getByTestId('create-variable-button')).toBeInTheDocument();
    });

    it('renders nothing without variable and without a create callback', () => {
      renderBar({ variables: [], canManage: true });
      expect(screen.queryByTestId('dashboard-variables-bar')).not.toBeInTheDocument();
    });
  });

  describe('chip menu', () => {
    it('is absent without edit and delete callbacks', () => {
      renderBar({ canManage: true });
      expect(screen.queryByRole('button', { name: /Open menu/ })).not.toBeInTheDocument();
    });

    it('forwards the edited and deleted variable', async () => {
      const onEdit = vi.fn();
      const onDelete = vi.fn();
      const { user } = renderBar({ canManage: true, onEdit, onDelete });
      await user.click(screen.getByRole('button', { name: 'Open menu: Country' }));
      await user.click(screen.getByRole('menuitem', { name: 'Edit variable' }));
      expect(onEdit).toHaveBeenCalledWith(country);
      await user.click(screen.getByRole('button', { name: 'Open menu: Sector' }));
      await user.click(screen.getByRole('menuitem', { name: 'Delete variable' }));
      expect(onDelete).toHaveBeenCalledWith(sector);
    });
  });
});
