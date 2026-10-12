import { useSyncExternalStore } from 'react';

// The provenance counts (Curation badges and counters) are aggregates that no mutation payload and no stream event
// update, and the freshness manager and the ingestion change them without this browser knowing: they are read again
// after each provenance action taken here, on a timer while the page is visible, and when it becomes visible again
// after a refresh it missed.
export const PROVENANCE_COUNTS_REFRESH_INTERVAL_MS = 2 * 60 * 1000;

let version = 0;
let missedWhileHidden = false;
let timer: ReturnType<typeof setInterval> | undefined;
const listeners = new Set<() => void>();

const isPageVisible = () => document.visibilityState === 'visible';

/** Reads the provenance counts again, after an action that changed conflicts or stale knowledge. */
export const refreshProvenanceCounts = () => {
  version += 1;
  missedWhileHidden = false;
  listeners.forEach((listener) => listener());
};

const onTick = () => {
  if (isPageVisible()) {
    refreshProvenanceCounts();
  } else {
    missedWhileHidden = true;
  }
};

const onVisibilityChange = () => {
  if (missedWhileHidden && isPageVisible()) {
    refreshProvenanceCounts();
  }
};

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  if (listeners.size === 1) {
    timer = setInterval(onTick, PROVENANCE_COUNTS_REFRESH_INTERVAL_MS);
    document.addEventListener('visibilitychange', onVisibilityChange);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      clearInterval(timer);
      timer = undefined;
      missedWhileHidden = false;
      document.removeEventListener('visibilitychange', onVisibilityChange);
    }
  };
};

const getVersion = () => version;

/** Relay fetch key of the provenance counts: it changes whenever they must be read again. */
const useProvenanceCountsFetchKey = () => useSyncExternalStore(subscribe, getVersion);

export default useProvenanceCountsFetchKey;
