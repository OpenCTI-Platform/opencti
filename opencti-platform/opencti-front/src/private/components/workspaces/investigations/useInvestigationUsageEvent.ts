import { useEffect, useRef } from 'react';
import { commitMutation, graphql } from 'react-relay';
import { environment } from '../../../../relay/environment';
import { InvestigationUsageEvent } from './__generated__/useInvestigationUsageEventMutation.graphql';

const investigationUsageEventMutation = graphql`
  mutation useInvestigationUsageEventMutation($id: ID!, $event: InvestigationUsageEvent!) {
    investigationUsageEvent(id: $id, event: $event)
  }
`;

// Telemetry is best effort and fully silent. This uses Relay's own commitMutation on purpose:
// the app's wrapper in relay/environment toasts GraphQL errors, and redirects on some of them,
// which would get in the way of the user.
export const trackInvestigationUsage = (investigationId: string, event: InvestigationUsageEvent) => {
  commitMutation(environment, {
    mutation: investigationUsageEventMutation,
    variables: { id: investigationId, event },
    onError: () => {},
  });
};

// Once per mount, including under StrictMode, whose simulated remount keeps refs.
// It deliberately keeps the first investigationId: the callers remount for each investigation.
export const useTrackInvestigationUsageOnMount = (investigationId: string, event: InvestigationUsageEvent) => {
  const hasBeenSent = useRef(false);
  useEffect(() => {
    if (hasBeenSent.current) return;
    hasBeenSent.current = true;
    trackInvestigationUsage(investigationId, event);
  }, []);
};
