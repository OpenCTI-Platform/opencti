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
  it('focuses the inline tag field when it opens, and closes it on Escape', async () => {
    const { user } = testRender(<WorkspaceHeaderTagManager tags={[]} workspaceId="workspace-1" canEdit />);

    await user.click(screen.getByRole('button', { name: 'Add tag' }));
    const field = await screen.findByLabelText('New tag');
    expect(field).toHaveFocus();

    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByLabelText('New tag')).not.toBeInTheDocument());
  });
});
