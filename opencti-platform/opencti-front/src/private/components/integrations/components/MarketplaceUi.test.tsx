import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import { Link } from 'react-router';
import testRender from '../../../../utils/tests/test-render';
import { DeployedCountChip } from './MarketplaceUi';

vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  APP_BASE_PATH: '/opencti',
}));

const DEPLOYED_TAB = '/dashboard/integrations/deployed?search=Abuse';

// The chip is rendered, as in the catalog cards and lines, inside a link.
const renderInCardLink = (to?: string) => testRender(
  <Link to="/dashboard/integrations/catalog/abuse">
    <DeployedCountChip count={2} to={to} />
  </Link>,
  { route: '/dashboard/integrations' },
);

afterEach(() => {
  vi.restoreAllMocks();
});

describe('DeployedCountChip', () => {
  it('opens the deployed tab, never the card link it is nested in', async () => {
    const { user } = renderInCardLink(DEPLOYED_TAB);
    await user.click(screen.getByRole('button'));
    expect(`${window.location.pathname}${window.location.search}`).toBe(DEPLOYED_TAB);
  });

  it('opens the deployed tab in a new tab under the base path on ctrl click', () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    renderInCardLink(DEPLOYED_TAB);
    fireEvent.click(screen.getByRole('button'), { ctrlKey: true });
    expect(open).toHaveBeenCalledWith(`/opencti${DEPLOYED_TAB}`, '_blank');
    expect(window.location.pathname).toBe('/dashboard/integrations');
  });

  it('opens the deployed tab on middle click instead of the card link', () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    renderInCardLink(DEPLOYED_TAB);
    const notCancelled = fireEvent(
      screen.getByRole('button'),
      new MouseEvent('auxclick', { bubbles: true, cancelable: true, button: 1 }),
    );
    expect(notCancelled).toBe(false);
    expect(open).toHaveBeenCalledWith(`/opencti${DEPLOYED_TAB}`, '_blank');
  });

  it('is a static chip without a target', () => {
    renderInCardLink();
    expect(screen.getByText('2 deployed')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});
