import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import WorkspaceHeaderTagManager from './WorkspaceHeaderTagManager';

vi.mock('src/utils/Security', () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
vi.mock('src/utils/hooks/useApiMutation', () => ({ default: () => [vi.fn()] }));

describe('WorkspaceHeaderTagManager', () => {
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
});
