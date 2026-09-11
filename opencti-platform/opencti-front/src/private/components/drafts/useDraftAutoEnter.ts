import { useEffect, useRef } from 'react';
import useDraftContext from '../../../utils/hooks/useDraftContext';

interface UseDraftAutoEnterArgs {
  draftId: string;
  /** When true, the draft is never entered (read-only draft). */
  disabled: boolean;
  enterDraft: (draftId: string) => void;
}

/**
 * Enters the draft a workspace URL points at, once per visit.
 *
 * The draft context is pushed to the client by the `me` subscription and can therefore change
 * while the workspace is displayed for reasons unrelated to this visit: the user exited the draft
 * from the toolbar, the draft was locked or deleted server side, or a payload describing an
 * earlier state was delivered late. Re-entering the draft on every such transition turned any
 * transient absence of the context into a server-side write, which put the session back into a
 * draft the user had just left (#18112). The entry is therefore requested only when the visit
 * starts outside of this draft, and never again for the same visit.
 */
const useDraftAutoEnter = ({ draftId, disabled, enterDraft }: UseDraftAutoEnterArgs) => {
  const draftContext = useDraftContext();
  // Draft for which this visit already is, or asked to be, inside.
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
