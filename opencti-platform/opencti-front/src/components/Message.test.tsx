import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import testRender from '../utils/tests/test-render';
import { MESSAGING$ } from '../relay/environment';
import Message from './Message';

describe('Message', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('should show a warning sent through the messaging service as a warning', async () => {
    testRender(<Message />);
    act(() => MESSAGING$.notifyWarning('Some variables are missing'));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Some variables are missing');
    expect(alert.className).toMatch(/Warning/);
  });

  it('should render the action of a success message and call it on click', async () => {
    const onClick = vi.fn();
    testRender(<Message />);
    act(() => MESSAGING$.notifySuccess('Observable created and added to the Report', { action: { label: 'Undo', onClick } }));
    const undo = await screen.findByRole('button', { name: 'Undo' });
    fireEvent.click(undo);
    expect(onClick).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.queryByText('Observable created and added to the Report')).toBeNull());
  });

  it('should keep the close button next to the action', async () => {
    const onClick = vi.fn();
    testRender(<Message />);
    act(() => MESSAGING$.notifySuccess('Observable created and added to the Report', { action: { label: 'Undo', onClick } }));
    const close = await screen.findByRole('button', { name: 'Close' });
    fireEvent.click(close);
    expect(onClick).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.queryByText('Observable created and added to the Report')).toBeNull());
  });

  it('should announce a message with an action as a status', async () => {
    testRender(<Message />);
    act(() => MESSAGING$.notifySuccess('Observable created and added to the Report', { action: { label: 'Undo', onClick: vi.fn() } }));
    const status = await screen.findByRole('status');
    expect(status).toHaveTextContent('Observable created and added to the Report');
  });

  it('should not hide a message with an action while it has focus', async () => {
    vi.useFakeTimers();
    testRender(<Message />);
    act(() => MESSAGING$.notifySuccess('Observable created and added to the Report', { action: { label: 'Undo', onClick: vi.fn() } }));
    // the messaging service is debounced
    await act(async () => { await vi.advanceTimersByTimeAsync(600); });
    const undo = screen.getByRole('button', { name: 'Undo' });
    act(() => undo.focus());
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
    expect(screen.queryByText('Observable created and added to the Report')).not.toBeNull();
    act(() => undo.blur());
    await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
    expect(screen.queryByText('Observable created and added to the Report')).toBeNull();
  });
});
