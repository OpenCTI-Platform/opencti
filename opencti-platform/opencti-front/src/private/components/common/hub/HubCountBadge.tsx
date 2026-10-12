import React, { Component, type ReactNode, Suspense, useCallback, useLayoutEffect, useState } from 'react';
import { Badge } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

/**
 * Counts the pending work of a hub entry (proposals to review, runs to triage); never a total. *retry* grows each time
 * the count is read again after a failure: a query passes it as its fetch key, so that it is fetched again.
 */
export type HubBadgeCount = (retry: number) => number | null | undefined;

export const COUNT_RETRY_DELAY_MS = 60000;

interface SilentBoundaryState {
  failed: boolean;
  retry: number;
}

// A count that cannot be read hides its badge until it is read again a while later: the menu and the tab bar never
// break for it, and a transient failure does not hide it until the next page load.
class SilentBoundary extends Component<{ children: (retry: number) => ReactNode }, SilentBoundaryState> {
  state: SilentBoundaryState = { failed: false, retry: 0 };

  private retryTimer?: ReturnType<typeof setTimeout>;

  static getDerivedStateFromError(): Partial<SilentBoundaryState> {
    return { failed: true };
  }

  componentDidCatch() {
    clearTimeout(this.retryTimer);
    this.retryTimer = setTimeout(() => this.setState(({ retry }) => ({ failed: false, retry: retry + 1 })), COUNT_RETRY_DELAY_MS);
  }

  componentWillUnmount() {
    clearTimeout(this.retryTimer);
  }

  render() {
    return this.state.failed ? null : this.props.children(this.state.retry);
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

const Count = ({ useCount, retry }: HubCountBadgeProps & { retry: number }) => {
  const count = useCount(retry);
  return <PendingBadge count={count} />;
};

/** The pending count of a hub entry, read without holding up the menu or the tab bar. */
const HubCountBadge = ({ useCount }: HubCountBadgeProps) => (
  <SilentBoundary>
    {(retry) => (
      <Suspense fallback={null}>
        <Count useCount={useCount} retry={retry} />
      </Suspense>
    )}
  </SilentBoundary>
);

/** One entry's count in a hub total, identified by the entry's stable id (its path). */
export interface HubCountSource {
  id: string;
  useCount: HubBadgeCount;
}

const CountReporter = ({ id, useCount, retry, onCount }: HubCountSource & {
  retry: number;
  onCount: (id: string, count: number | null) => void;
}) => {
  const count = useCount(retry) ?? 0;
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
          {(retry) => (
            <Suspense fallback={null}>
              <CountReporter id={id} useCount={useCount} retry={retry} onCount={onCount} />
            </Suspense>
          )}
        </SilentBoundary>
      ))}
      <PendingBadge count={total} />
    </>
  );
};

export default HubCountBadge;
