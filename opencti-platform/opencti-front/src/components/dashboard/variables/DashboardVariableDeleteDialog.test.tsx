import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { DashboardVariable } from '../dashboard-types';
import DashboardVariableDeleteDialog from './DashboardVariableDeleteDialog';

const sector: DashboardVariable = {
  id: '11111111-1111-4111-8111-111111111111',
  name: 'Sector',
  type: 'text',
  restriction: { mode: 'none' },
  defaultValue: 'Energy',
};

const renderDialog = (props: {
  widgets?: { id: string; title: string }[];
  onConfirm?: () => Promise<void>;
  onClose?: () => void;
} = {}) => {
  const onConfirm = props.onConfirm ?? vi.fn().mockResolvedValue(undefined);
  const onClose = props.onClose ?? vi.fn();
  const rendered = testRender(
    <DashboardVariableDeleteDialog
      open
      variable={sector}
      widgets={props.widgets ?? []}
      onConfirm={onConfirm}
      onClose={onClose}
    />,
  );
  return { ...rendered, onConfirm, onClose };
};

const dialog = () => screen.getByTestId('dashboard-variable-delete-dialog');

describe('DashboardVariableDeleteDialog', () => {
  it('lists the impacted widgets by title when the variable is used', () => {
    renderDialog({ widgets: [{ id: 'w1', title: 'Top malwares' }, { id: 'w2', title: 'Reports' }] });
    expect(within(dialog()).getByText(/will show “No data has been found”/)).toBeInTheDocument();
    const items = within(dialog()).getAllByRole('listitem');
    expect(items.map((item) => item.textContent)).toEqual(['Top malwares', 'Reports']);
  });

  it('only asks for a confirmation, without any list, when no widget uses the variable', () => {
    renderDialog();
    expect(within(dialog()).getByText(/Do you want to delete the variable/)).toBeInTheDocument();
    expect(within(dialog()).queryByRole('list')).not.toBeInTheDocument();
    expect(within(dialog()).queryByText(/No data has been found/)).not.toBeInTheDocument();
  });

  it('confirms, then closes', async () => {
    const { user, onConfirm, onClose } = renderDialog();
    await user.click(screen.getByTestId('dashboard-variable-delete-confirm'));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
  });

  it('does nothing but close on Cancel', async () => {
    const { user, onConfirm, onClose } = renderDialog();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onConfirm).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('stays open when the deletion fails, without an unhandled rejection', async () => {
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    const onConfirm = vi.fn().mockRejectedValue(new Error('denied'));
    const { user, onClose } = renderDialog({ onConfirm });
    await user.click(screen.getByTestId('dashboard-variable-delete-confirm'));
    await waitFor(() => expect(screen.getByTestId('dashboard-variable-delete-confirm')).toBeEnabled());
    await new Promise((resolve) => setTimeout(resolve, 0));
    process.off('unhandledRejection', unhandled);
    expect(unhandled).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    expect(dialog()).toBeInTheDocument();
  });

  it('disables the confirmation while the deletion is pending', async () => {
    let resolve: () => void = () => {};
    const onConfirm = vi.fn(() => new Promise<void>((done) => {
      resolve = done;
    }));
    const { user, onClose } = renderDialog({ onConfirm });
    await user.click(screen.getByTestId('dashboard-variable-delete-confirm'));
    expect(screen.getByTestId('dashboard-variable-delete-confirm')).toBeDisabled();
    resolve();
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
  });
});
