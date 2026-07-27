import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import useDraftCommentPopup from './useDraftCommentPopup';

const DRAFT_ID = 'draft-123';
const STORAGE_KEY = `opencti-draft-comment-seen-${DRAFT_ID}`;

const ENTRY = { comment: 'Please fix the TLP', timestamp: '2024-01-01T00:00:00Z' };

describe('useDraftCommentPopup', () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.clearAllMocks();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it('shows the popup when the timestamp has never been seen', () => {
    const { result } = renderHook(() => useDraftCommentPopup(DRAFT_ID, ENTRY));
    expect(result.current.showCommentPopup).toBe(true);
  });

  it('does not show the popup when the timestamp is already stored', () => {
    window.localStorage.setItem(STORAGE_KEY, ENTRY.timestamp);
    const { result } = renderHook(() => useDraftCommentPopup(DRAFT_ID, ENTRY));
    expect(result.current.showCommentPopup).toBe(false);
  });

  it('does not show the popup when lastHistoryEntry is null', () => {
    const { result } = renderHook(() => useDraftCommentPopup(DRAFT_ID, null));
    expect(result.current.showCommentPopup).toBe(false);
  });

  it('does not show the popup when comment is empty', () => {
    const { result } = renderHook(() => useDraftCommentPopup(DRAFT_ID, { comment: '', timestamp: ENTRY.timestamp }));
    expect(result.current.showCommentPopup).toBe(false);
  });

  it('does not show the popup when comment is null', () => {
    const { result } = renderHook(() => useDraftCommentPopup(DRAFT_ID, { comment: null, timestamp: ENTRY.timestamp }));
    expect(result.current.showCommentPopup).toBe(false);
  });

  it('handleClose closes the popup', () => {
    const { result } = renderHook(() => useDraftCommentPopup(DRAFT_ID, ENTRY));
    expect(result.current.showCommentPopup).toBe(true);
    act(() => result.current.handleClose());
    expect(result.current.showCommentPopup).toBe(false);
  });

  it('handleClose writes the timestamp to localStorage so the popup never re-opens', () => {
    const { result } = renderHook(() => useDraftCommentPopup(DRAFT_ID, ENTRY));
    act(() => result.current.handleClose());
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(ENTRY.timestamp);
  });

  it('does not write localStorage before the user closes the popup', () => {
    renderHook(() => useDraftCommentPopup(DRAFT_ID, ENTRY));
    // The popup is open but the user hasn't closed it yet
    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('shows the popup again for a new timestamp after the previous one was closed', () => {
    // Simulate a previous session where the user already saw the first popup
    const firstEntry = { comment: 'First comment', timestamp: '2024-01-01T00:00:00Z' };
    window.localStorage.setItem(STORAGE_KEY, firstEntry.timestamp);

    const secondEntry = { comment: 'Second comment', timestamp: '2024-02-01T00:00:00Z' };
    const { result } = renderHook(() => useDraftCommentPopup(DRAFT_ID, secondEntry));

    expect(result.current.showCommentPopup).toBe(true);
  });
});
