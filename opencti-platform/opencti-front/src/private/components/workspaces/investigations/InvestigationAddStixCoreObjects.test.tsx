import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import InvestigationAddStixCoreObjects from './InvestigationAddStixCoreObjects';

// The panel lists and creates platform entities: these tests only check when it opens and closes.
vi.mock('../../common/drawer/Drawer', () => ({
  default: ({ open, title, onClose }: { open: boolean; title: string; onClose: () => void }) => (open ? (
    <div role="dialog" aria-label={title}>
      <button type="button" onClick={onClose}>Close panel</button>
    </div>
  ) : null),
}));
vi.mock('../../../../utils/hooks/useAttributes', () => ({ default: () => ({ stixDomainObjectTypes: [], stixCyberObservableTypes: [] }) }));
vi.mock('../../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useAuth')>()),
  default: () => ({ platformModuleHelpers: { isRuntimeFieldEnable: () => false } }),
}));
vi.mock('../../../../utils/hooks/useLocalStorage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useLocalStorage')>()),
  usePaginationLocalStorage: () => ({ viewStorage: {}, helpers: {}, paginationOptions: {} }),
}));

const ADD = 'Add an entity to this investigation';

describe('InvestigationAddStixCoreObjects', () => {
  it('opens the panel when the graph says so, and hands the + button and closing back to the graph', async () => {
    const onOpenChange = vi.fn();
    const { user, rerender } = testRender(<InvestigationAddStixCoreObjects workspaceId="investigation-1" open={false} onOpenChange={onOpenChange} />);
    expect(screen.queryByRole('dialog', { name: 'Add entities' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: ADD }));
    expect(onOpenChange).toHaveBeenLastCalledWith(true);

    rerender(<InvestigationAddStixCoreObjects workspaceId="investigation-1" open onOpenChange={onOpenChange} />);
    expect(screen.getByRole('dialog', { name: 'Add entities' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Close panel' }));
    expect(onOpenChange).toHaveBeenLastCalledWith(false);
  });

  it('opens and closes the panel from the + button on its own, without open or onOpenChange', async () => {
    const { user } = testRender(<InvestigationAddStixCoreObjects workspaceId="investigation-1" />);
    expect(screen.queryByRole('dialog', { name: 'Add entities' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: ADD }));
    expect(screen.getByRole('dialog', { name: 'Add entities' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Close panel' }));
    expect(screen.queryByRole('dialog', { name: 'Add entities' })).not.toBeInTheDocument();
  });
});
