import { useEffect, useRef } from 'react';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import useSwitchDraft from './useSwitchDraft';

const useAutoEnterDraft = (draftId: string, isDraftReadOnly: boolean) => {
  const draftContext = useDraftContext();
  const { t_i18n } = useFormatter();
  const { enterDraft } = useSwitchDraft();
  const entry = useRef({ draftId, handled: false });

  useEffect(() => {
    if (entry.current.draftId !== draftId) {
      entry.current = { draftId, handled: false };
    }
    const currentEntry = entry.current;
    if (draftContext?.id === draftId) {
      currentEntry.handled = true;
    }
    // A cleared context after entry is an exit, not a request to re-enter the same route.
    if (!isDraftReadOnly && !currentEntry.handled) {
      currentEntry.handled = true;
      enterDraft(draftId, {
        onCompleted: () => {
          MESSAGING$.notifySuccess(<span>{t_i18n('You are now in Draft Mode')}</span>);
        },
        onError: (error) => {
          currentEntry.handled = false;
          MESSAGING$.notifyRelayError(error);
        },
      });
    }
  }, [draftContext, draftId, enterDraft, isDraftReadOnly, t_i18n]);
};

export default useAutoEnterDraft;
