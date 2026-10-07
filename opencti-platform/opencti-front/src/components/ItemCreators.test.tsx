import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../utils/tests/test-render';
import { SETTINGS_SETACCESSES } from '../utils/hooks/useGranted';
import ItemCreators from './ItemCreators';

vi.mock('../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../relay/environment')>()),
  APP_BASE_PATH: '/opencti',
}));

const USER_PAGE = '/dashboard/settings/accesses/users/user-1';

const renderCreators = (capabilities: { name: string }[]) => testRender(
  <ItemCreators creators={[{ id: 'user-1', name: 'Jane Doe' }]} />,
  {
    route: '/dashboard/analyses/reports',
    userContext: createMockUserContext({ me: { name: 'admin', capabilities } }),
  },
);

afterEach(() => {
  vi.restoreAllMocks();
});

describe('ItemCreators', () => {
  it('opens the creator page on click', async () => {
    const { user } = renderCreators([{ name: SETTINGS_SETACCESSES }]);
    await user.click(screen.getByRole('button', { name: 'Jane Doe' }));
    expect(window.location.pathname).toBe(USER_PAGE);
  });

  it('opens the creator page in a new tab under the base path on ctrl click and middle click', () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    renderCreators([{ name: SETTINGS_SETACCESSES }]);
    const chip = screen.getByRole('button', { name: 'Jane Doe' });
    fireEvent.click(chip, { ctrlKey: true });
    fireEvent(chip, new MouseEvent('auxclick', { bubbles: true, cancelable: true, button: 1 }));
    expect(open).toHaveBeenCalledTimes(2);
    expect(open).toHaveBeenNthCalledWith(1, `/opencti${USER_PAGE}`, '_blank');
    expect(open).toHaveBeenNthCalledWith(2, `/opencti${USER_PAGE}`, '_blank');
    expect(window.location.pathname).toBe('/dashboard/analyses/reports');
  });

  it('is a static chip without access to the users', () => {
    renderCreators([]);
    expect(screen.getByText('Jane Doe')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});
