import { ReactNode } from 'react';
import { ErrorBoundary } from '../../private/components/Error';
import type { Widget, WidgetContext } from '../../utils/widget/widget';
import DashboardRawViz from './DashboardRawViz';
import DashboardRelationshipsViz from './DashboardRelationshipsViz';
import DashboardAuditsViz from './DashboardAuditsViz';
import DashboardEntitiesViz from './DashboardEntitiesViz';
import type { DashboardConfig } from './dashboard-types';

interface DashboardVizProps {
  widget: Widget;
  config: DashboardConfig;
  context?: WidgetContext;
  popover?: ReactNode;
}

const DashboardViz = ({ widget, config, popover, context }: DashboardVizProps) => {
  const { perspective } = widget;
  return (
    <ErrorBoundary>
      <>
        {perspective === 'entities' && (
          <DashboardEntitiesViz widget={widget} config={config} popover={popover} context={context} />
        )}
        {perspective === 'relationships' && (
          <DashboardRelationshipsViz widget={widget} config={config} popover={popover} context={context} />
        )}
        {perspective === 'audits' && (
          <DashboardAuditsViz widget={widget} config={config} popover={popover} context={context} />
        )}
        {perspective === null && (
          <DashboardRawViz widget={widget} popover={popover} />
        )}
      </>
    </ErrorBoundary>
  );
};

export default DashboardViz;
