import React, { ReactNode } from 'react';
import { useFormatter } from '../i18n';
import WidgetNoData from './WidgetNoData';

type GraphQLResponseError = { message?: string; extensions?: { code?: string; data?: { reason?: string } } };

// Errors of a GraphQL response, as thrown by the network layer
const getResponseErrors = (error: unknown): GraphQLResponseError[] => {
  const responseError = error as { res?: { errors?: GraphQLResponseError[] }; data?: { res?: { errors?: GraphQLResponseError[] } } } | null;
  return responseError?.res?.errors ?? responseError?.data?.res?.errors ?? [];
};

// The reasons of the refusals are read from extensions.data.reason, never from their messages
const BreakdownRefusal = ({ reasons }: { reasons: (string | undefined)[] }) => {
  const { t_i18n } = useFormatter();
  let message = t_i18n('This breakdown cannot be computed with the settings of this widget. Edit the widget to change them.');
  if (reasons.includes('too_large')) {
    message = t_i18n('This breakdown has too many points for the selected period. Shorten the period, choose a coarser interval or reduce the number of series.');
  } else if (reasons.includes('too_many_values')) {
    message = t_i18n('There are too many values to find the lowest ones. Choose the highest values or narrow the filters of this widget.');
  }
  return <WidgetNoData message={message} />;
};

interface WidgetBreakdownErrorBoundaryProps {
  children: ReactNode;
  // A new value (a new query) clears the error
  resetKey: unknown;
}

interface WidgetBreakdownErrorBoundaryState {
  error: unknown;
  resetKey: unknown;
}

/**
 * The breakdown API refuses the requests it cannot serve (too many points for the period, too many values
 * to rank the lowest ones, settings it does not support): the widget says why and keeps its menu, instead
 * of being replaced by the error of the whole widget. Any other error goes on to the enclosing error boundary.
 */
class WidgetBreakdownErrorBoundary extends React.Component<WidgetBreakdownErrorBoundaryProps, WidgetBreakdownErrorBoundaryState> {
  constructor(props: WidgetBreakdownErrorBoundaryProps) {
    super(props);
    this.state = { error: null, resetKey: props.resetKey };
  }

  static getDerivedStateFromError(error: unknown) {
    return { error };
  }

  static getDerivedStateFromProps(props: WidgetBreakdownErrorBoundaryProps, state: WidgetBreakdownErrorBoundaryState) {
    return props.resetKey !== state.resetKey ? { error: null, resetKey: props.resetKey } : null;
  }

  render() {
    const { error } = this.state;
    if (error) {
      const refusals = getResponseErrors(error).filter((responseError) => responseError.extensions?.code === 'FUNCTIONAL_ERROR');
      if (refusals.length === 0) {
        throw error;
      }
      return <BreakdownRefusal reasons={refusals.map((refusal) => refusal.extensions?.data?.reason)} />;
    }
    return this.props.children;
  }
}

export default WidgetBreakdownErrorBoundary;
