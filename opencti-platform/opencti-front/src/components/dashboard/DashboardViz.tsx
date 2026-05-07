import { ReactNode } from 'react';
import { ErrorBoundary } from '../../private/components/Error';
import type { Widget, WidgetHost } from '../../utils/widget/widget';
import DashboardRawViz from './DashboardRawViz';
import DashboardRelationshipsViz from './DashboardRelationshipsViz';
import DashboardAuditsViz from './DashboardAuditsViz';
import DashboardEntitiesViz from './DashboardEntitiesViz';
import type { DashboardConfig } from './dashboard-types';

interface DashboardVizProps {
  widget: Widget;
  config: DashboardConfig;
  host?: WidgetHost;
  popover?: ReactNode;
}

const DashboardViz = ({ widget, config, popover, host }: DashboardVizProps) => {
  const { perspective } = widget;
  return (
    <ErrorBoundary>
      <>
        {perspective === 'entities' && (
          <DashboardEntitiesViz widget={widget} config={config} popover={popover} host={host} />
        )}
        {perspective === 'relationships' && (
          <DashboardRelationshipsViz widget={widget} config={config} popover={popover} host={host} />
        )}
        {perspective === 'audits' && (
          <DashboardAuditsViz widget={widget} config={config} popover={popover} host={host} />
        )}
        {perspective === null && (
          <DashboardRawViz widget={widget} popover={popover} />
        )}
      </>
    </ErrorBoundary>
  );
};

export default DashboardViz;
