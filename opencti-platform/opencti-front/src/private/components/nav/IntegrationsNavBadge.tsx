import React, { Suspense } from 'react';
import { PreloadedQuery } from 'react-relay';
import NavBadge from './NavBadge';
import useIntegrationsNavBadge from './useIntegrationsNavBadge';
import { useIntegrationsNavBadgeQuery } from './__generated__/useIntegrationsNavBadgeQuery.graphql';

interface IntegrationsNavBadgeProps {
  queryRef: PreloadedQuery<useIntegrationsNavBadgeQuery>;
  compact: boolean;
}

// A failing status lookup hides the badge, never the navigation
class HideOnError extends React.Component<{ children: React.ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    return this.state.failed ? null : this.props.children;
  }
}

const IntegrationsNavBadgeContent: React.FC<IntegrationsNavBadgeProps> = ({ queryRef, compact }) => {
  const badge = useIntegrationsNavBadge(queryRef);
  return badge ? <NavBadge badge={badge} compact={compact} /> : null;
};

// The connector statuses can take longer than the navigation: while they load, the row shows no badge
const IntegrationsNavBadge: React.FC<IntegrationsNavBadgeProps> = (props) => (
  <HideOnError>
    <Suspense fallback={null}>
      <IntegrationsNavBadgeContent {...props} />
    </Suspense>
  </HideOnError>
);

export default IntegrationsNavBadge;
