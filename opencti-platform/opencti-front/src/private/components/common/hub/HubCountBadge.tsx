import React, { Component, type ReactNode, Suspense, useCallback, useEffect, useState } from 'react';
import { Badge } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

/** Counts the pending work of a hub entry (proposals to review, runs to triage); never a total. */
export type HubBadgeCount = () => number | null | undefined;

interface SilentBoundaryState {
  failed: boolean;
}

// A count that cannot be read hides its badge: the menu and the tab bar never break for it.
class SilentBoundary extends Component<{ children: ReactNode }, SilentBoundaryState> {
  state: SilentBoundaryState = { failed: false };

  static getDerivedStateFromError(): SilentBoundaryState {
    return { failed: true };
  }

  render() {
    return this.state.failed ? null : this.props.children;
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

const CountReporter = ({ useCount, index, onCount }: HubCountBadgeProps & {
  index: number;
  onCount: (index: number, count: number) => void;
}) => {
  const count = useCount() ?? 0;
  useEffect(() => onCount(index, count), [index, count, onCount]);
  return null;
};

/** The pending work of a whole hub, the sum of its entries' counts: the badge of its menu item. */
export const HubTotalBadge = ({ counts }: { counts: HubBadgeCount[] }) => {
  const [values, setValues] = useState<Record<number, number>>({});
  const onCount = useCallback((index: number, count: number) => {
    setValues((current) => (current[index] === count ? current : { ...current, [index]: count }));
  }, []);
  const total = Object.values(values).reduce((sum, count) => sum + count, 0);
  return (
    <>
      {counts.map((useCount, index) => (
        <SilentBoundary key={index}>
          <Suspense fallback={null}>
            <CountReporter useCount={useCount} index={index} onCount={onCount} />
          </Suspense>
        </SilentBoundary>
      ))}
      <PendingBadge count={total} />
    </>
  );
};

export default HubCountBadge;
