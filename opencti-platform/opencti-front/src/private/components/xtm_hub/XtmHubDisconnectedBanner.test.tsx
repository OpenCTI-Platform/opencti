import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import XtmHubDisconnectedBanner from './XtmHubDisconnectedBanner';

const mockNavigate = vi.fn();

vi.mock('react-router', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('XtmHubDisconnectedBanner', () => {
  it('renders the title and subtitle', () => {
    testRender(<XtmHubDisconnectedBanner />);
    expect(screen.getByText('XTM Hub is disconnected')).toBeInTheDocument();
    expect(screen.getByText('Please connect your product so you can deploy resources')).toBeInTheDocument();
  });

  it('renders the connect button', () => {
    testRender(<XtmHubDisconnectedBanner />);
    expect(screen.getByRole('button', { name: 'Connect product to XTM Hub' })).toBeInTheDocument();
  });

  it('navigates to the XTM Hub connect redirect when the button is clicked', async () => {
    const { user } = testRender(<XtmHubDisconnectedBanner />);
    await user.click(screen.getByRole('button', { name: 'Connect product to XTM Hub' }));
    expect(mockNavigate).toHaveBeenCalledWith('/redirect/connect-xtm-hub');
  });

  it('renders the unreachable subtitle without the connect button, keeping the title', () => {
    testRender(<XtmHubDisconnectedBanner unreachable />);
    expect(screen.getByText('XTM Hub is disconnected')).toBeInTheDocument();
    expect(screen.getByText("XTM Hub is unreachable and connection can't be established")).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Connect product to XTM Hub' })).not.toBeInTheDocument();
  });
});
