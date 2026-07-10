import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import FintelDesignPopover from './FintelDesignPopover';

const { commitSetDefaultMock, fetchQueryMock, toPromiseMock } = vi.hoisted(() => ({
  commitSetDefaultMock: vi.fn(),
  fetchQueryMock: vi.fn(),
  toPromiseMock: vi.fn(),
}));

vi.mock('../../../../utils/hooks/useApiMutation', () => ({
  default: () => [commitSetDefaultMock],
}));

vi.mock('src/relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('src/relay/environment')>();
  return {
    ...actual,
    fetchQuery: fetchQueryMock,
    handleError: vi.fn(),
  };
});

describe('Component: FintelDesignPopover', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    toPromiseMock.mockResolvedValue({});
    fetchQueryMock.mockReturnValue({ toPromise: toPromiseMock });
  });

  it('should display update, set as default and delete in this order', async () => {
    const { user } = testRender(
      <FintelDesignPopover
        fintelDesignId="design-1"
        isDefault={false}
        onUpdate={vi.fn()}
        onDelete={vi.fn()}
      />,
    );

    await user.click(screen.getByRole('button'));

    const menuItems = screen.getAllByRole('menuitem');
    expect(menuItems.map((item) => item.textContent)).toEqual([
      'Update',
      'Set as default',
      'Delete',
    ]);
  });

  it('should display remove default instead of set as default when design is default', async () => {
    const { user } = testRender(
      <FintelDesignPopover
        fintelDesignId="design-1"
        isDefault
        onUpdate={vi.fn()}
        onDelete={vi.fn()}
      />,
    );

    await user.click(screen.getByRole('button'));

    const menuItems = screen.getAllByRole('menuitem');
    expect(menuItems.map((item) => item.textContent)).toEqual([
      'Update',
      'Remove default',
      'Delete',
    ]);
  });

  it('should call onUpdate when clicking update', async () => {
    const onUpdate = vi.fn();
    const { user } = testRender(
      <FintelDesignPopover
        fintelDesignId="design-1"
        isDefault={false}
        onUpdate={onUpdate}
      />,
    );

    await user.click(screen.getByRole('button'));
    await user.click(screen.getByRole('menuitem', { name: 'Update' }));

    expect(onUpdate).toHaveBeenCalledTimes(1);
  });

  it('should call onDelete when clicking delete', async () => {
    const onDelete = vi.fn();
    const { user } = testRender(
      <FintelDesignPopover
        fintelDesignId="design-1"
        isDefault={false}
        onDelete={onDelete}
      />,
    );

    await user.click(screen.getByRole('button'));
    await user.click(screen.getByRole('menuitem', { name: 'Delete' }));

    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  it('should open replace dialog when another default already exists', async () => {
    const { user } = testRender(
      <FintelDesignPopover
        fintelDesignId="design-1"
        isDefault={false}
        currentDefaultName="Existing default design"
      />,
    );

    await user.click(screen.getByRole('button'));
    await user.click(screen.getByRole('menuitem', { name: 'Set as default' }));

    expect(screen.getByText('Replace default design?')).toBeInTheDocument();
    expect(screen.getByText(/Existing default design/i)).toBeInTheDocument();
    expect(commitSetDefaultMock).not.toHaveBeenCalled();
  });
});
