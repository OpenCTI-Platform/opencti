import React, { Component, createContext, type ReactNode, Suspense, useCallback, useContext, useLayoutEffect, useState } from 'react';
import { Badge } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

/** Counts the pending work of a hub entry (proposals to review, runs to triage); never a total. */
export type HubBadgeCount = () => number | null | undefined;

interface SilentBoundaryState {
  failed: boolean;
  retries: number;
}

// First retry of a count that failed, doubled at each new failure up to the longest one
export const COUNT_RETRY_DELAY_MS = 30 * 1000;
const COUNT_MAX_RETRY_DELAY_MS = 10 * 60 * 1000;

const CountRetryContext = createContext(0);

/**
 * Number of times the count was read again after a failure, 0 before any. A count that caches its result for its
 * request (a Relay query keeps the error for the same fetch key) adds it to that key, so that a retry asks again.
 */
export const useHubCountRetryKey = () => useContext(CountRetryContext);

// A count that cannot be read hides its badge: the menu and the tab bar never break for it. It is read again
// later, so that a transient failure does not hide the badge until the page is reloaded.
class SilentBoundary extends Component<{ children: ReactNode }, SilentBoundaryState> {
  state: SilentBoundaryState = { failed: false, retries: 0 };

  retryTimer: ReturnType<typeof setTimeout> | undefined;

  static getDerivedStateFromError(): Partial<SilentBoundaryState> {
    return { failed: true };
  }

  componentDidCatch() {
    clearTimeout(this.retryTimer);
    const delay = Math.min(COUNT_RETRY_DELAY_MS * 2 ** this.state.retries, COUNT_MAX_RETRY_DELAY_MS);
    this.retryTimer = setTimeout(() => this.setState(({ retries }) => ({ failed: false, retries: retries + 1 })), delay);
  }

  componentWillUnmount() {
    clearTimeout(this.retryTimer);
  }

  render() {
    if (this.state.failed) {
      return null;
    }
    return <CountRetryContext.Provider value={this.state.retries}>{this.props.children}</CountRetryContext.Provider>;
  }
}

interface HubCountBadgeProps {
  useCount: HubBadgeCount;
}

const PendingBadge = ({ count }: { count: number | null | undefined }) => {
  const { t_i18n } = useFormatter();
  if (!count || count <= 0) {
    return null;
  }
  return (
    <Badge
      content={count}
      tone="brand"
      accessibleText={t_i18n('{count} pending', { values: { count } })}
    />
  );
};

const Count = ({ useCount }: HubCountBadgeProps) => {
  const count = useCount();
  return <PendingBadge count={count} />;
};

/** The pending count of a hub entry, read without holding up the menu or the tab bar. */
const HubCountBadge = ({ useCount }: HubCountBadgeProps) => (
  <SilentBoundary>
    <Suspense fallback={null}>
      <Count useCount={useCount} />
    </Suspense>
  </SilentBoundary>
);

/** One entry's count in a hub total, identified by the entry's stable id (its path). */
export interface HubCountSource {
  id: string;
  useCount: HubBadgeCount;
}

const CountReporter = ({ id, useCount, onCount }: HubCountSource & {
  onCount: (id: string, count: number | null) => void;
}) => {
  const count = useCount() ?? 0;
  // A layout effect: its cleanup also runs when Suspense hides a count that suspends again, so an
  // entry that unmounts, fails or suspends takes its contribution out of the total.
  useLayoutEffect(() => {
    onCount(id, count);
    return () => onCount(id, null);
  }, [id, count, onCount]);
  return null;
};

/** The pending work of a whole hub, the sum of its entries' counts: the badge of its menu item. */
export const HubTotalBadge = ({ counts }: { counts: HubCountSource[] }) => {
  const [values, setValues] = useState<Record<string, number>>({});
  const onCount = useCallback((id: string, count: number | null) => {
    setValues((current) => {
      if (count === null) {
        if (!(id in current)) return current;
        const next = { ...current };
        delete next[id];
        return next;
      }
      return current[id] === count ? current : { ...current, [id]: count };
    });
  }, []);
  const total = Object.values(values).reduce((sum, count) => sum + count, 0);
  return (
    <>
      {counts.map(({ id, useCount }) => (
        <SilentBoundary key={id}>
          <Suspense fallback={null}>
            <CountReporter id={id} useCount={useCount} onCount={onCount} />
          </Suspense>
        </SilentBoundary>
      ))}
      <PendingBadge count={total} />
    </>
  );
};

export default HubCountBadge;
