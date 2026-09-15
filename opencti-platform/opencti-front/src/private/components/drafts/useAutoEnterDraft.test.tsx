import { act, renderHook } from '@testing-library/react';
import { StrictMode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import useAutoEnterDraft from './useAutoEnterDraft';

const { mockDraftContext, mockEnterDraft, mockNotifyError, translate } = vi.hoisted(() => ({
  mockDraftContext: vi.fn(),
  mockEnterDraft: vi.fn(),
  mockNotifyError: vi.fn(),
  translate: (text: string) => text,
}));

vi.mock('../../../utils/hooks/useDraftContext', () => ({ default: mockDraftContext }));
vi.mock('./useSwitchDraft', () => ({ default: () => ({ enterDraft: mockEnterDraft }) }));
vi.mock('../../../components/i18n', () => ({
  useFormatter: () => ({ t_i18n: translate }),
}));
vi.mock('../../../relay/environment', () => ({
  MESSAGING$: { notifySuccess: vi.fn(), notifyRelayError: mockNotifyError },
}));

describe('useAutoEnterDraft', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockDraftContext.mockReturnValue(null);
  });

  it('does not re-enter when an existing draft context is cleared before navigation completes', () => {
    mockDraftContext.mockReturnValue({ id: 'draft-1' });
    const { rerender } = renderHook(() => useAutoEnterDraft('draft-1', false));
    expect(mockEnterDraft).not.toHaveBeenCalled();

    mockDraftContext.mockReturnValue(null);
    rerender();
    expect(mockEnterDraft).not.toHaveBeenCalled();
  });

  it('enters once, including Strict Mode effect replay, and does not undo a later exit', () => {
    const { rerender } = renderHook(() => useAutoEnterDraft('draft-1', false), {
      wrapper: StrictMode,
    });
    expect(mockEnterDraft).toHaveBeenCalledTimes(1);
    expect(mockEnterDraft).toHaveBeenCalledWith('draft-1', expect.any(Object));

    mockDraftContext.mockReturnValue({ id: 'draft-1' });
    rerender();
    mockDraftContext.mockReturnValue(null);
    rerender();
    expect(mockEnterDraft).toHaveBeenCalledTimes(1);
  });

  it('enters a different draft when the route changes and can revisit the original draft', () => {
    mockDraftContext.mockReturnValue({ id: 'draft-1' });
    const { rerender } = renderHook(({ id }) => useAutoEnterDraft(id, false), {
      initialProps: { id: 'draft-1' },
    });

    rerender({ id: 'draft-2' });
    expect(mockEnterDraft).toHaveBeenLastCalledWith('draft-2', expect.any(Object));
    mockDraftContext.mockReturnValue({ id: 'draft-2' });
    rerender({ id: 'draft-1' });
    expect(mockEnterDraft).toHaveBeenLastCalledWith('draft-1', expect.any(Object));
    expect(mockEnterDraft).toHaveBeenCalledTimes(2);
  });

  it('does not enter a read-only draft but enters if it becomes editable', () => {
    const { rerender } = renderHook(({ readOnly }) => useAutoEnterDraft('draft-1', readOnly), {
      initialProps: { readOnly: true },
    });
    expect(mockEnterDraft).not.toHaveBeenCalled();
    rerender({ readOnly: false });
    expect(mockEnterDraft).toHaveBeenCalledTimes(1);
  });

  it('reports failed entry and allows a later attempt', () => {
    const { rerender } = renderHook(({ readOnly }) => useAutoEnterDraft('draft-1', readOnly), {
      initialProps: { readOnly: false },
    });
    const error = new Error('Entry failed');
    act(() => mockEnterDraft.mock.calls[0][1].onError(error));
    expect(mockNotifyError).toHaveBeenCalledWith(error);
    rerender({ readOnly: true });
    rerender({ readOnly: false });
    expect(mockEnterDraft).toHaveBeenCalledTimes(2);
  });

  it('does not retry the current draft when an earlier route entry fails', () => {
    const { rerender } = renderHook(({ id, readOnly }) => useAutoEnterDraft(id, readOnly), {
      initialProps: { id: 'draft-1', readOnly: false },
    });
    const firstEntry = mockEnterDraft.mock.calls[0][1];
    rerender({ id: 'draft-2', readOnly: false });
    act(() => firstEntry.onError(new Error('Previous draft entry failed')));

    rerender({ id: 'draft-2', readOnly: true });
    rerender({ id: 'draft-2', readOnly: false });
    expect(mockEnterDraft).toHaveBeenCalledTimes(2);
  });
});
