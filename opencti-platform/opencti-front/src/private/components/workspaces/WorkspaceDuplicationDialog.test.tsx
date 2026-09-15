import React from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import WorkspaceDuplicationDialog from './WorkspaceDuplicationDialog';
import { WorkspaceDuplicationDialogFragment$key } from './__generated__/WorkspaceDuplicationDialogFragment.graphql';

const mocks = vi.hoisted(() => ({
  commit: vi.fn(),
  handleError: vi.fn(),
  notifySuccess: vi.fn(),
  translate: (value: string) => value,
}));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    graphql: (query: TemplateStringsArray) => query,
    useFragment: (_fragment: unknown, data: unknown) => data,
  };
});

vi.mock('../../../components/i18n', () => ({
  useFormatter: () => ({ t_i18n: mocks.translate }),
}));

vi.mock('../../../utils/hooks/useApiMutation', () => ({
  default: () => [mocks.commit],
}));

vi.mock('../../../relay/environment', () => ({
  handleError: mocks.handleError,
  MESSAGING$: { notifySuccess: mocks.notifySuccess },
}));

vi.mock('@common/dialog/Dialog', () => ({
  default: ({ open, title, children }: { open: boolean; title: string; children: React.ReactNode }) => (
    open ? <div role="dialog" aria-label={title}>{children}</div> : null
  ),
}));

vi.mock('@common/button/Button', () => ({
  default: ({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button type="button" {...props}>{children}</button>
  ),
}));

vi.mock('@mui/material/DialogActions', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock('@filigran/design-system', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@filigran/design-system')>();
  return {
    ...actual,
    Input: ({ error, label, ...props }: React.InputHTMLAttributes<HTMLInputElement> & { error?: string; label?: string }) => (
      <label>
        {label}
        <input {...props} aria-invalid={Boolean(error)} />
        {error && <span>{error}</span>}
      </label>
    ),
  };
});

vi.mock('react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router')>();
  return {
    ...actual,
    Link: ({ children, to }: { children: React.ReactNode; to: string }) => <a href={to}>{children}</a>,
  };
});

describe('WorkspaceDuplicationDialog', () => {
  const workspace = {
    id: 'workspace-id',
    name: 'Source workspace',
    type: 'dashboard',
  };

  const renderDialog = (overrides = {}) => {
    const props = {
      data: workspace as unknown as WorkspaceDuplicationDialogFragment$key,
      displayDuplicate: true,
      duplicating: false,
      handleCloseDuplicate: vi.fn(),
      setDuplicating: vi.fn(),
      ...overrides,
    };
    return { ...testRender(<WorkspaceDuplicationDialog {...props} />), props };
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('submits the edited workspace name and resets the busy state on success', async () => {
    const { user, props } = renderDialog();
    const input = screen.getByRole('textbox');
    await user.clear(input);
    await user.type(input, 'Copied dashboard');
    await user.click(screen.getByRole('button', { name: 'Duplicate' }));

    expect(props.setDuplicating).toHaveBeenCalledWith(true);
    expect(mocks.commit).toHaveBeenCalledWith(expect.objectContaining({
      variables: {
        id: 'workspace-id',
        name: 'Copied dashboard',
      },
    }));
    const mutation = mocks.commit.mock.calls[0][0];
    mutation.onCompleted({ workspaceDuplicate: { id: 'duplicated-id' } }, null);

    expect(props.handleCloseDuplicate).toHaveBeenCalledOnce();
    expect(props.setDuplicating).toHaveBeenLastCalledWith(false);
    expect(mocks.notifySuccess).toHaveBeenCalledOnce();
  });

  it('clears the busy state and reports mutation errors', async () => {
    const { user, props } = renderDialog();
    await user.click(screen.getByRole('button', { name: 'Duplicate' }));

    const mutation = mocks.commit.mock.calls[0][0];
    const error = new Error('mutation failed');
    mutation.onError(error);

    expect(mocks.handleError).toHaveBeenCalledWith(error);
    expect(props.setDuplicating).toHaveBeenLastCalledWith(false);
    expect(props.handleCloseDuplicate).not.toHaveBeenCalled();
  });

  it('shows investigation wording and skips the dashboard notification in paginated views', async () => {
    const { user, props } = renderDialog({
      data: { ...workspace, type: 'investigation' },
      paginationOptions: { count: 10 },
    });
    expect(screen.getByRole('dialog', { name: 'Duplicate the investigation' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Duplicate' }));
    expect(mocks.commit).toHaveBeenCalledWith(expect.objectContaining({
      variables: { id: 'workspace-id', name: 'Source workspace - copy' },
    }));
    const mutation = mocks.commit.mock.calls[0][0];
    mutation.onCompleted({ workspaceDuplicate: { id: 'duplicated-investigation-id' } }, null);

    expect(props.handleCloseDuplicate).toHaveBeenCalledOnce();
    expect(mocks.notifySuccess).not.toHaveBeenCalled();
  });

  it.each(['dashboard', 'investigation'])('links to the duplicated %s using its mutation response', async (type) => {
    const { user } = renderDialog({ data: { ...workspace, type } });
    await user.click(screen.getByRole('button', { name: 'Duplicate' }));

    mocks.commit.mock.calls[0][0].onCompleted({ workspaceDuplicate: { id: 'duplicated-id' } }, null);
    testRender(mocks.notifySuccess.mock.calls[0][0]);

    expect(screen.getByRole('link', { name: 'here' })).toHaveAttribute('href', `/dashboard/workspaces/${type}s/duplicated-id`);
  });

  it.each(['dashboard', 'investigation'])('forwards the updater for a %s duplication', async (type) => {
    const updater = vi.fn();
    const { user } = renderDialog({ data: { ...workspace, type }, updater });
    await user.click(screen.getByRole('button', { name: 'Duplicate' }));

    const store = {};
    mocks.commit.mock.calls[0][0].updater(store);

    expect(updater).toHaveBeenCalledWith(store);
  });

  it('does not duplicate an unsupported workspace type', async () => {
    const { user } = renderDialog({ data: { ...workspace, type: 'unsupported' } });
    const button = screen.getByRole('button', { name: 'Duplicate' });
    expect(button).toBeDisabled();
    await user.click(button);
    expect(mocks.commit).not.toHaveBeenCalled();
  });

  it('disables submission for an empty name and restores the source name on reopen', async () => {
    const { user, rerender, props } = renderDialog();
    const input = screen.getByRole('textbox');
    await user.clear(input);

    expect(screen.getByRole('button', { name: 'Duplicate' })).toBeDisabled();
    expect(screen.getByText('This field is required')).toBeInTheDocument();

    rerender(<WorkspaceDuplicationDialog {...props} displayDuplicate={false} />);
    rerender(<WorkspaceDuplicationDialog {...props} displayDuplicate={true} />);

    expect(screen.getByRole('textbox')).toHaveValue('Source workspace - copy');
  });

  it('keeps submission disabled while another duplication is running', () => {
    renderDialog({ duplicating: true });
    expect(screen.getByRole('button', { name: 'Duplicate' })).toBeDisabled();
  });

  it('updates the controlled name while editing', () => {
    renderDialog();
    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: 'New name' } });
    expect(input).toHaveValue('New name');
  });
});
