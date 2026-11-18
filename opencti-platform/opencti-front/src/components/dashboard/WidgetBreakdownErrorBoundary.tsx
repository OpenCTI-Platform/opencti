import React, { ReactNode } from 'react';
import { useFormatter } from '../i18n';
import WidgetNoData from './WidgetNoData';
import { getGraphQLResponseErrors } from '../../relay/graphQLResponseErrors';

// The reasons of the refusals are read from extensions.data.reason, never from their messages.
// Read only, the refusal only says why: its reader cannot change the widget, nor its period.
const BreakdownRefusal = ({ reasons, readOnly }: { reasons: (string | undefined)[]; readOnly: boolean }) => {
  const { t_i18n } = useFormatter();
  let message = readOnly
    ? t_i18n('This breakdown cannot be computed with the settings of this widget.')
    : t_i18n('This breakdown cannot be computed with the settings of this widget. Edit the widget to change them.');
  if (reasons.includes('too_large')) {
    message = readOnly
      ? t_i18n('This breakdown has too many points for the selected period.')
      : t_i18n('This breakdown has too many points for the selected period. Shorten the period, choose a coarser interval or reduce the number of series.');
  } else if (reasons.includes('too_many_values')) {
    message = readOnly
      ? t_i18n('There are too many values to find the lowest ones.')
      : t_i18n('There are too many values to find the lowest ones. Choose the highest values or narrow the filters of this widget.');
  } else if (reasons.includes('unsupported_date_attribute')) {
    message = readOnly
      ? t_i18n('The date attribute of this widget does not apply to its data.')
      : t_i18n('The date attribute of this widget does not apply to its data. Edit the widget to choose another date attribute.');
  } else if (reasons.includes('unsupported_field')) {
    message = readOnly
      ? t_i18n('The breakdown field of this widget does not apply to its data.')
      : t_i18n('The breakdown field of this widget does not apply to its data. Edit the widget to choose another field.');
  } else if (reasons.includes('invalid_limit')) {
    message = readOnly
      ? t_i18n('The number of series of this widget must be between 1 and 50.')
      : t_i18n('The number of series of this widget must be between 1 and 50. Edit the widget to change it.');
  }
  return <WidgetNoData message={message} />;
};

interface WidgetBreakdownErrorBoundaryProps {
  children: ReactNode;
  // A new value (a new query) clears the error
  resetKey: unknown;
  // For the readers who cannot edit the widget, like the visitors of a public dashboard: no advice
  readOnly?: boolean;
}

interface WidgetBreakdownErrorBoundaryState {
  error: unknown;
  resetKey: unknown;
}

/**
 * The breakdown API refuses the requests it cannot serve (too many points for the period, too many values
 * to rank the lowest ones, settings it does not support): the widget says why, in place of its chart.
 * The error boundary of WidgetContainer, which keeps the menu of the widget all the same, would only show
 * a generic error, and keep it until the page changes: this one is cleared by the next query of the widget
 * (`resetKey`), once its settings are changed or it is refreshed. Any other error goes on to that boundary.
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
      const refusals = getGraphQLResponseErrors(error).filter((responseError) => responseError.extensions?.code === 'FUNCTIONAL_ERROR');
      if (refusals.length === 0) {
        throw error;
      }
      return <BreakdownRefusal reasons={refusals.map((refusal) => refusal.extensions?.data?.reason)} readOnly={this.props.readOnly ?? false} />;
    }
    return this.props.children;
  }
}

export default WidgetBreakdownErrorBoundary;
