import { useEffect, useState } from 'react';

const DRAFT_COMMENT_SEEN_PREFIX = 'opencti-draft-comment-seen-';

interface LastHistoryEntry {
  comment?: string | null;
  timestamp: string;
}

interface UseDraftCommentPopupResult {
  showCommentPopup: boolean;
  handleClose: () => void;
}

const useDraftCommentPopup = (
  draftId: string,
  lastHistoryEntry: LastHistoryEntry | null | undefined,
): UseDraftCommentPopupResult => {
  const [showCommentPopup, setShowCommentPopup] = useState(false);

  useEffect(() => {
    if (!lastHistoryEntry?.comment || !lastHistoryEntry?.timestamp) return;
    const storageKey = `${DRAFT_COMMENT_SEEN_PREFIX}${draftId}`;
    const seenTimestamp = window.localStorage.getItem(storageKey);
    if (seenTimestamp !== lastHistoryEntry.timestamp) {
      setShowCommentPopup(true);
    }
  }, [draftId, lastHistoryEntry]);

  const handleClose = () => {
    if (lastHistoryEntry?.timestamp) {
      const storageKey = `${DRAFT_COMMENT_SEEN_PREFIX}${draftId}`;
      window.localStorage.setItem(storageKey, lastHistoryEntry.timestamp);
    }
    setShowCommentPopup(false);
  };

  return { showCommentPopup, handleClose };
};

export default useDraftCommentPopup;
