import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { DashboardVariable } from '../dashboard-types';
import { EXPORT_REMOVE_CLASS } from '../../../utils/Image';
import DashboardVariablesBar from './DashboardVariablesBar';

vi.mock('./useVariableValueLabels', () => ({
  default: (_variable: unknown, values: string[]) => ({ labels: new Map(values.map((value) => [value, value])), restricted: new Set() }),
  useVariablesValueLabels: (current: { id: string; value: string | undefined }[]) => new Map(current.map(({ id, value }) => [
    id,
    { labels: new Map(value ? [[value, value]] : []), restricted: new Set() },
  ])),
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
type User = ReturnType<typeof testRender>['user'];

const openSaveMenu = (user: User) => user.click(screen.getByTestId('dashboard-save-menu'));
const setAsDefaults = async (user: User) => {
  await openSaveMenu(user);
  await user.click(await screen.findByTestId('dashboard-set-as-defaults'));
};

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

  it('warns on the chip of a variable whose default value is not valid, and only on that one', () => {
    const quantity: DashboardVariable = { id: 'var-3', name: 'Quantity', type: 'numeric', restriction: { mode: 'none' }, defaultValue: ' 42' };
    renderBar({ variables: [sector, country, quantity] });
    expect(screen.getByTestId('dashboard-variable-chip-Quantity')).toHaveAttribute('data-invalid-default', 'true');
    expect(screen.getByTestId('dashboard-variable-chip-Sector')).not.toHaveAttribute('data-invalid-default');
    expect(screen.getByTestId('dashboard-variable-chip-Country')).not.toHaveAttribute('data-invalid-default');
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

  it('hides Reset and the Modified badge while nothing differs from the defaults, the Save menu staying for a manager', async () => {
    const { user } = renderBar({ canManage: true });
    expect(screen.queryByTestId('dashboard-values-reset')).not.toBeInTheDocument();
    expect(screen.queryByTestId('dashboard-values-modified')).not.toBeInTheDocument();
    await openSaveMenu(user);
    expect(await screen.findByTestId('dashboard-set-as-defaults')).toHaveAttribute('data-disabled');
  });

  it('treats a null default and an empty value as equal', () => {
    renderBar({ canManage: true, values: new Map([['var-1', 'Energy'], ['var-2', '']]) });
    expect(screen.queryByTestId('dashboard-values-reset')).not.toBeInTheDocument();
    expect(screen.getByTestId('dashboard-variable-chip-Country')).not.toHaveAttribute('data-modified');
  });

  it('flags the departure: the Modified badge, and a dot on the changed chip only', () => {
    renderBar({ values: new Map([['var-1', 'Finance']]) });
    expect(screen.getByTestId('dashboard-values-modified')).toHaveTextContent('Modified');
    expect(screen.getByTestId('dashboard-variable-chip-Sector')).toHaveAttribute('data-modified', 'true');
    expect(screen.getByTestId('dashboard-variable-chip-Country')).not.toHaveAttribute('data-modified');
  });

  it('shows Reset to a viewer when a value differs, and never the Save menu', async () => {
    const { user, onReset } = renderBar({ values: new Map([['var-1', 'Finance']]) });
    expect(screen.queryByTestId('dashboard-save-menu')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Reset to defaults' }));
    expect(onReset).toHaveBeenCalledTimes(1);
  });

  it('names the default preset Reset goes back to', () => {
    renderBar({ values: new Map([['var-1', 'Finance']]), resetTargetName: 'Finance' });
    expect(screen.getByTestId('dashboard-values-reset')).toHaveTextContent('Reset to “Finance”');
  });

  it('lets a manager set the current values as defaults, and disables the actions meanwhile', async () => {
    let finish: () => void = () => {};
    const onSetAsDefaults = vi.fn(() => new Promise<void>((resolve) => {
      finish = resolve;
    }));
    const { user } = renderBar({ canManage: true, values: new Map([['var-2', 'France']]), onSetAsDefaults });
    await setAsDefaults(user);
    expect(onSetAsDefaults).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('dashboard-save-menu')).toBeDisabled();
    expect(screen.getByTestId('dashboard-values-reset')).toBeDisabled();
    finish();
    await waitFor(() => expect(screen.getByTestId('dashboard-values-reset')).toBeEnabled());
    expect(screen.getByTestId('dashboard-save-menu')).toBeEnabled();
  });

  it('makes the chips inert while the values are being saved, so no value changes meanwhile', async () => {
    let finish: () => void = () => {};
    const onSetAsDefaults = vi.fn(() => new Promise<void>((resolve) => {
      finish = resolve;
    }));
    const { user } = renderBar({ canManage: true, values: new Map([['var-1', 'Energy'], ['var-2', 'France']]), onSetAsDefaults });
    expect(screen.getByRole('button', { name: 'Country : France' })).toBeEnabled();
    await setAsDefaults(user);
    const chip = screen.getByRole('button', { name: 'Country : France' });
    expect(chip).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeDisabled();
    await user.click(chip);
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    finish();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Country : France' })).toBeEnabled());
    expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeEnabled();
  });

  it('offers the update of the active preset, enabled only once it is modified', async () => {
    const { user, unmount } = renderBar({ canManage: true, activePresetName: 'Finance', onUpdatePreset: vi.fn() });
    await openSaveMenu(user);
    expect(await screen.findByTestId('dashboard-preset-update')).toHaveAttribute('data-disabled');
    unmount();
    const onUpdatePreset = vi.fn();
    const modified = renderBar({ canManage: true, activePresetName: 'Finance', isActivePresetModified: true, onUpdatePreset });
    await openSaveMenu(modified.user);
    await modified.user.click(await screen.findByTestId('dashboard-preset-update'));
    expect(onUpdatePreset).toHaveBeenCalledOnce();
  });

  it('marks the action buttons for removal from an image export, not the chips', () => {
    renderBar({ canManage: true, onCreate: vi.fn(), values: new Map([['var-1', 'Energy'], ['var-2', 'France']]) });
    expect(screen.getByTestId('dashboard-values-reset').closest(`.${EXPORT_REMOVE_CLASS}`)).not.toBeNull();
    expect(screen.getByTestId('dashboard-save-menu').closest(`.${EXPORT_REMOVE_CLASS}`)).not.toBeNull();
    expect(screen.getByTestId('dashboard-values-modified').closest(`.${EXPORT_REMOVE_CLASS}`)).not.toBeNull();
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

  describe('chip actions', () => {
    it('are absent without edit and delete callbacks', async () => {
      const { user } = renderBar({ canManage: true });
      await user.click(screen.getByRole('button', { name: /^Country :/ }));
      expect(screen.queryByTestId('dashboard-variable-edit')).not.toBeInTheDocument();
      expect(screen.queryByTestId('dashboard-variable-delete')).not.toBeInTheDocument();
    });

    it('forwards the edited and deleted variable', async () => {
      const onEdit = vi.fn();
      const onDelete = vi.fn();
      const { user } = renderBar({ canManage: true, onEdit, onDelete });
      await user.click(screen.getByRole('button', { name: /^Country :/ }));
      await user.click(screen.getByRole('button', { name: 'Edit variable' }));
      expect(onEdit).toHaveBeenCalledWith(country);
      await user.click(screen.getByRole('button', { name: /^Sector :/ }));
      await user.click(screen.getByRole('button', { name: 'Delete variable' }));
      expect(onDelete).toHaveBeenCalledWith(sector);
    });
  });

  it('shows Reset when a preset other than the default one is active, even without any changed value', () => {
    renderBar({ variables: [sector], isPresetSelected: true });
    expect(screen.getByTestId('dashboard-values-reset')).toBeInTheDocument();
    // Not a departure from that preset: no Modified badge.
    expect(screen.queryByTestId('dashboard-values-modified')).not.toBeInTheDocument();
  });

  it('shows Reset, Modified and an enabled Set as dashboard defaults when only the time range is modified', async () => {
    const { user } = renderBar({ variables: [sector], canManage: true, isTimeRangeModified: true });
    expect(screen.getByTestId('dashboard-values-reset')).toBeInTheDocument();
    expect(screen.getByTestId('dashboard-values-modified')).toBeInTheDocument();
    await openSaveMenu(user);
    expect(await screen.findByTestId('dashboard-set-as-defaults')).not.toHaveAttribute('data-disabled');
  });

  it('shows the actions after the create button when there is no variable but the time range is modified', () => {
    renderBar({ variables: [], canManage: true, onCreate: vi.fn(), isTimeRangeModified: true });
    expect(screen.getByRole('button', { name: 'Variable' })).toBeInTheDocument();
    expect(screen.getByTestId('dashboard-values-reset')).toBeInTheDocument();
  });

  it('renders the leading pill first, then the Modified badge', () => {
    renderBar({ leading: <span data-testid="leading-pill">pill</span>, values: new Map([['var-1', 'Finance']]) });
    const bar = screen.getByTestId('dashboard-variables-bar');
    expect(bar.firstElementChild).toBe(screen.getByTestId('leading-pill'));
    expect(screen.getByTestId('leading-pill').nextElementSibling).toBe(screen.getByTestId('dashboard-values-modified'));
  });
});
