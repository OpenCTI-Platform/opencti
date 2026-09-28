import { useEffect, useRef } from 'react';
import useDraftContext from '../../../utils/hooks/useDraftContext';

interface UseDraftAutoEnterArgs {
  draftId: string;
  /** When true, the draft is never entered (read-only draft). */
  disabled: boolean;
  enterDraft: (draftId: string) => void;
}

/** Enters the draft a workspace URL points at, once per visit. */
const useDraftAutoEnter = ({ draftId, disabled, enterDraft }: UseDraftAutoEnterArgs) => {
  const draftContext = useDraftContext();
  const handledDraftId = useRef<string | null>(null);

  useEffect(() => {
    if (handledDraftId.current === draftId) {
      return;
    }
    if (draftContext?.id === draftId) {
      handledDraftId.current = draftId;
      return;
    }
    if (disabled) {
      return;
    }
    handledDraftId.current = draftId;
    enterDraft(draftId);
  }, [draftContext, draftId, disabled, enterDraft]);
};

export default useDraftAutoEnter;
