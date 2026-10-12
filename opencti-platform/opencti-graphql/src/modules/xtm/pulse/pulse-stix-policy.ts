import { PulseAccess } from '../../../generated/graphql';
import type { PulseResolvedCandidate } from './pulse-settings';

// What the OpenCTI STIX extension may carry of the community data: the conversion to STIX is synchronous and runs on
// every node (streams, exports), so it reads a snapshot of the current access, scope, pending cleanup and marking
// policy that each node refreshes in the background. Until a node read it, nothing is carried.
export interface PulseStixPolicy {
  access: PulseAccess;
  scopes: string[];
  // While a cleanup that failed waits for its replay, the stored data may be out of date: none of it is carried.
  cleanupPending: boolean;
  // The full experience only: whether the object may leave the platform now. It reads the object's current markings
  // and access, so an object that just got an excluded marking or restricted members never carries data the next
  // cycle has not cleared yet.
  isContributable: ((instance: PulseResolvedCandidate) => boolean) | null;
}

const REFRESH_INTERVAL_MS = 30 * 1000;

let policy: PulseStixPolicy | null = null;
let refreshedAt = 0;
let refreshing = false;
let refresher: (() => Promise<PulseStixPolicy>) | null = null;

export const setPulseStixPolicy = (next: PulseStixPolicy | null) => {
  policy = next;
  refreshedAt = Date.now();
};

export const refreshPulseStixPolicy = async () => {
  if (!refresher) {
    return;
  }
  setPulseStixPolicy(await refresher());
};

export const registerPulseStixPolicyRefresher = (load: () => Promise<PulseStixPolicy>) => {
  refresher = load;
};

const refreshInBackground = () => {
  if (!refresher || refreshing || Date.now() - refreshedAt < REFRESH_INTERVAL_MS) {
    return;
  }
  refreshing = true;
  refreshPulseStixPolicy()
    // A failed read hides the data until the next one succeeds.
    .catch(() => setPulseStixPolicy(null))
    .finally(() => {
      refreshing = false;
    });
};

interface PulseStoredFields extends PulseResolvedCandidate {
  pulse_information?: { preview?: boolean } | null;
}

// Whether the stored community data of the object may be carried now, as the GraphQL field would show it: in scope,
// the preview signal alone in the preview, the network data alone in the full experience and only for an object that
// may leave the platform.
export const isPulseStixVisible = (instance: PulseStoredFields) => {
  refreshInBackground();
  if (!policy || policy.cleanupPending || !policy.scopes.includes(instance.entity_type)) {
    return false;
  }
  const preview = instance.pulse_information?.preview === true;
  if (policy.access === PulseAccess.Preview) {
    return preview;
  }
  return policy.access === PulseAccess.Full && !preview && policy.isContributable !== null && policy.isContributable(instance);
};
