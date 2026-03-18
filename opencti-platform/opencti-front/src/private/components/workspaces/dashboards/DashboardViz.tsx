import { ReactNode } from 'react';
import { ErrorBoundary } from '../../Error';
import type { Widget } from '../../../../utils/widget/widget';
import DashboardRawViz from './DashboardRawViz';
import DashboardRelationshipsViz from './DashboardRelationshipsViz';
import DashboardAuditsViz from './DashboardAuditsViz';
import DashboardEntitiesViz from './DashboardEntitiesViz';
import type { DashboardConfig } from '../../../../utils/dashboard';

interface DashboardVizProps {
  widget: Widget;
  config: DashboardConfig;
  popover?: ReactNode;
}

const DashboardViz = ({ widget, config, popover }: DashboardVizProps) => {
  const { perspective } = widget;
  return (
    <ErrorBoundary>
      <>
        {perspective === 'entities' && (
          <DashboardEntitiesViz widget={widget} config={config} popover={popover} />
        )}
        {perspective === 'relationships' && (
          <DashboardRelationshipsViz widget={widget} config={config} popover={popover} />
        )}
        {perspective === 'audits' && (
          <DashboardAuditsViz widget={widget} config={config} popover={popover} />
        )}
        {perspective === null && (
          <DashboardRawViz widget={widget} popover={popover} />
        )}
      </>
    </ErrorBoundary>
  );
};

export default DashboardViz;
