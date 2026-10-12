import { createElement, StrictMode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import { commitMutation } from 'react-relay';
import { environment, MESSAGING$ } from '../../../../relay/environment';
import { trackInvestigationUsage, useTrackInvestigationUsageOnMount } from './useInvestigationUsageEvent';

vi.mock('react-relay', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-relay')>(),
  commitMutation: vi.fn(),
}));
vi.mock('../../../../relay/environment', () => ({
  environment: {},
  MESSAGING$: { messages: { next: vi.fn() }, notifyError: vi.fn() },
}));

describe('trackInvestigationUsage', () => {
  beforeEach(() => {
    vi.mocked(commitMutation).mockClear();
    vi.mocked(MESSAGING$.messages.next).mockClear();
    vi.mocked(MESSAGING$.notifyError).mockClear();
  });

  it('commits the mutation once, on the app environment, with the id and the event', () => {
    trackInvestigationUsage('id', 'OPENED');

    expect(commitMutation).toHaveBeenCalledTimes(1);
    expect(vi.mocked(commitMutation).mock.calls[0][0]).toBe(environment);
    expect(vi.mocked(commitMutation).mock.calls[0][1].variables).toEqual({ id: 'id', event: 'OPENED' });
  });

  it('swallows errors', () => {
    trackInvestigationUsage('id', 'OPENED');

    const { onError } = vi.mocked(commitMutation).mock.calls[0][1];
    expect(onError).toBeTypeOf('function');
    expect(() => onError?.(new Error('network down'))).not.toThrow();
  });

  it('stays silent on a GraphQL error', () => {
    trackInvestigationUsage('id', 'OPENED');

    const { onError } = vi.mocked(commitMutation).mock.calls[0][1];
    const graphQLError = Object.assign(new Error('Forbidden'), { res: { errors: [{ message: 'Forbidden' }] } });
    expect(() => onError?.(graphQLError)).not.toThrow();
    expect(MESSAGING$.messages.next).not.toHaveBeenCalled();
    expect(MESSAGING$.notifyError).not.toHaveBeenCalled();
  });
});

describe('useTrackInvestigationUsageOnMount', () => {
  beforeEach(() => {
    vi.mocked(commitMutation).mockClear();
  });

  const render = () => renderHook(
    () => useTrackInvestigationUsageOnMount('id', 'MATRIX_VIEWED'),
    { wrapper: ({ children }) => createElement(StrictMode, null, children) },
  );

  it('sends the event once under StrictMode', () => {
    render();

    expect(commitMutation).toHaveBeenCalledTimes(1);
    expect(vi.mocked(commitMutation).mock.calls[0][1].variables).toEqual({ id: 'id', event: 'MATRIX_VIEWED' });
  });

  it('sends the event again after unmount and remount', () => {
    const { unmount } = render();
    unmount();
    render();

    expect(commitMutation).toHaveBeenCalledTimes(2);
  });

  it('does not resend on re-render', () => {
    const { rerender } = render();
    rerender();

    expect(commitMutation).toHaveBeenCalledTimes(1);
  });
});
