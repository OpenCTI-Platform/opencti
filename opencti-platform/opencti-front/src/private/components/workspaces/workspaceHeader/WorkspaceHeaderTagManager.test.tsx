import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import WorkspaceHeaderTagManager from './WorkspaceHeaderTagManager';

vi.mock('src/utils/Security', () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
const mocks = vi.hoisted(() => ({ commit: vi.fn() }));

vi.mock('src/utils/hooks/useApiMutation', () => ({ default: () => [mocks.commit] }));

describe('WorkspaceHeaderTagManager', () => {
  beforeEach(() => vi.clearAllMocks());

  it('focuses the inline tag field when it opens, and closes it on Escape back to its trigger', async () => {
    const { user } = testRender(<WorkspaceHeaderTagManager tags={[]} workspaceId="workspace-1" canEdit />);

    await user.click(screen.getByRole('button', { name: 'Add tag' }));
    const field = await screen.findByLabelText('New tag');
    expect(field).toHaveFocus();

    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByLabelText('New tag')).not.toBeInTheDocument());
    expect(screen.getByRole('button', { name: 'Add tag' })).toHaveFocus();
  });

  it('moves the focus to "More" when adding a second tag replaces the "Add tag" trigger', async () => {
    const { user, rerender } = testRender(<WorkspaceHeaderTagManager tags={['first']} workspaceId="workspace-1" canEdit />);

    await user.click(screen.getByRole('button', { name: 'Add tag' }));
    await user.type(await screen.findByLabelText('New tag'), 'second{Enter}');
    expect(screen.getByRole('button', { name: 'Add tag' })).toHaveFocus();

    // The mutation's store update re-renders the header with both tags.
    rerender(<WorkspaceHeaderTagManager tags={['first', 'second']} workspaceId="workspace-1" canEdit />);
    expect(screen.getByRole('button', { name: 'More' })).toHaveFocus();
  });

  it('focuses the new tag field when the "More" dialog opens', async () => {
    const { user } = testRender(<WorkspaceHeaderTagManager tags={['first', 'second']} workspaceId="workspace-1" canEdit />);

    await user.click(screen.getByRole('button', { name: 'More' }));
    await screen.findByRole('dialog', { name: 'Entity tags' });
    await waitFor(() => expect(screen.getByLabelText('New tag')).toHaveFocus());
  });

  it('adds a tag from the "More" dialog with the Add button or with Enter', async () => {
    const { user } = testRender(<WorkspaceHeaderTagManager tags={['first', 'second']} workspaceId="workspace-1" canEdit />);
    await user.click(screen.getByRole('button', { name: 'More' }));
    const dialog = await screen.findByRole('dialog', { name: 'Entity tags' });

    await user.type(within(dialog).getByLabelText('New tag'), 'third');
    await user.click(within(dialog).getByRole('button', { name: 'Add' }));
    expect(mocks.commit).toHaveBeenCalledOnce();
    expect(mocks.commit.mock.calls[0][0].variables.input).toEqual({ key: 'tags', value: ['first', 'second', 'third'] });

    await user.type(within(dialog).getByLabelText('New tag'), 'fourth{Enter}');
    expect(mocks.commit).toHaveBeenCalledTimes(2);
  });

  it('adds nothing from the "More" dialog when the field is empty', async () => {
    const { user } = testRender(<WorkspaceHeaderTagManager tags={['first', 'second']} workspaceId="workspace-1" canEdit />);
    await user.click(screen.getByRole('button', { name: 'More' }));
    const dialog = await screen.findByRole('dialog', { name: 'Entity tags' });

    await user.click(within(dialog).getByRole('button', { name: 'Add' }));
    expect(mocks.commit).not.toHaveBeenCalled();
  });
});
