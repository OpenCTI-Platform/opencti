import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useDraftContext, { DraftContext } from '../../../utils/hooks/useDraftContext';
import useDraftAutoEnter from './useDraftAutoEnter';

vi.mock('../../../utils/hooks/useDraftContext', () => ({
  default: vi.fn(),
  DRAFT_TOOLBAR_HEIGHT: 69,
}));

const DRAFT_ID = 'draft-1';
const OTHER_DRAFT_ID = 'draft-2';

const inDraft = (id: string): DraftContext => ({
  id,
  name: `Draft ${id}`,
  draft_status: 'open',
  processingCount: 0,
  currentUserAccessRight: 'admin',
});

const mockedUseDraftContext = vi.mocked(useDraftContext);

interface Props {
  draftId: string;
  disabled: boolean;
  enterDraft: (draftId: string) => void;
}

const renderAutoEnter = (props: Props) => renderHook((p: Props) => useDraftAutoEnter(p), { initialProps: props });

describe('useDraftAutoEnter', () => {
  const enterDraft = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('enters the draft when the visit starts outside of any draft', () => {
    mockedUseDraftContext.mockReturnValue(null);
    renderAutoEnter({ draftId: DRAFT_ID, disabled: false, enterDraft });
    expect(enterDraft).toHaveBeenCalledTimes(1);
    expect(enterDraft).toHaveBeenCalledWith(DRAFT_ID);
  });

  it('enters the draft when the visit starts inside another draft', () => {
    mockedUseDraftContext.mockReturnValue(inDraft(OTHER_DRAFT_ID));
    renderAutoEnter({ draftId: DRAFT_ID, disabled: false, enterDraft });
    expect(enterDraft).toHaveBeenCalledTimes(1);
    expect(enterDraft).toHaveBeenCalledWith(DRAFT_ID);
  });

  it('does not enter the draft when the visit starts inside it', () => {
    mockedUseDraftContext.mockReturnValue(inDraft(DRAFT_ID));
    renderAutoEnter({ draftId: DRAFT_ID, disabled: false, enterDraft });
    expect(enterDraft).not.toHaveBeenCalled();
  });

  it('does not enter a read-only draft', () => {
    mockedUseDraftContext.mockReturnValue(null);
    renderAutoEnter({ draftId: DRAFT_ID, disabled: true, enterDraft });
    expect(enterDraft).not.toHaveBeenCalled();
  });

  it('requests the entry once per visit, however many times the workspace renders', () => {
    mockedUseDraftContext.mockReturnValue(null);
    const { rerender } = renderAutoEnter({ draftId: DRAFT_ID, disabled: false, enterDraft });
    rerender({ draftId: DRAFT_ID, disabled: false, enterDraft: vi.fn() });
    rerender({ draftId: DRAFT_ID, disabled: false, enterDraft });
    expect(enterDraft).toHaveBeenCalledTimes(1);
  });

  // #18112: the context is cleared by the exit mutation, by a server-side eviction, or by a late
  // subscription payload; none of these is a reason to put the session back into the draft.
  it('does not re-enter the draft when the context is cleared during the visit', () => {
    mockedUseDraftContext.mockReturnValue(inDraft(DRAFT_ID));
    const { rerender } = renderAutoEnter({ draftId: DRAFT_ID, disabled: false, enterDraft });
    expect(enterDraft).not.toHaveBeenCalled();

    mockedUseDraftContext.mockReturnValue(null);
    rerender({ draftId: DRAFT_ID, disabled: false, enterDraft });
    expect(enterDraft).not.toHaveBeenCalled();
  });

  it('does not re-enter the draft when the context is cleared after the entry it requested', () => {
    mockedUseDraftContext.mockReturnValue(null);
    const { rerender } = renderAutoEnter({ draftId: DRAFT_ID, disabled: false, enterDraft });
    expect(enterDraft).toHaveBeenCalledTimes(1);

    mockedUseDraftContext.mockReturnValue(inDraft(DRAFT_ID));
    rerender({ draftId: DRAFT_ID, disabled: false, enterDraft });
    mockedUseDraftContext.mockReturnValue(null);
    rerender({ draftId: DRAFT_ID, disabled: false, enterDraft });
    expect(enterDraft).toHaveBeenCalledTimes(1);
  });

  it('starts over when the workspace switches to another draft', () => {
    mockedUseDraftContext.mockReturnValue(inDraft(DRAFT_ID));
    const { rerender } = renderAutoEnter({ draftId: DRAFT_ID, disabled: false, enterDraft });
    expect(enterDraft).not.toHaveBeenCalled();

    rerender({ draftId: OTHER_DRAFT_ID, disabled: false, enterDraft });
    expect(enterDraft).toHaveBeenCalledTimes(1);
    expect(enterDraft).toHaveBeenCalledWith(OTHER_DRAFT_ID);
  });
});
