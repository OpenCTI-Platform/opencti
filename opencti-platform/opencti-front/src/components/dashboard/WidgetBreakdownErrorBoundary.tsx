import React, { ReactNode } from 'react';
import { useFormatter } from '../i18n';
import WidgetNoData from './WidgetNoData';

type GraphQLResponseError = { message?: string; extensions?: { code?: string } };

// Errors of a GraphQL response, as thrown by the network layer
const getResponseErrors = (error: unknown): GraphQLResponseError[] => {
  const responseError = error as { res?: { errors?: GraphQLResponseError[] }; data?: { res?: { errors?: GraphQLResponseError[] } } } | null;
  return responseError?.res?.errors ?? responseError?.data?.res?.errors ?? [];
};

const BreakdownRefusal = ({ isTooLarge }: { isTooLarge: boolean }) => {
  const { t_i18n } = useFormatter();
  return (
    <WidgetNoData
      message={isTooLarge
        ? t_i18n('This breakdown has too many points for the selected period. Reduce the period, the interval or the number of series.')
        : t_i18n('This breakdown cannot be computed with the settings of this widget. Edit the widget to change them.')}
    />
  );
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
 * The breakdown API refuses the requests it cannot serve (too many points for the period, settings it does
 * not support): the widget says why and keeps its menu, instead of being replaced by the error of the whole
 * widget. Any other error goes on to the enclosing error boundary.
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
      return <BreakdownRefusal isTooLarge={refusals.some((refusal) => refusal.message?.includes('too large'))} />;
    }
    return this.props.children;
  }
}

export default WidgetBreakdownErrorBoundary;
